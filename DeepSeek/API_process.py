import pandas as pd
from openai import OpenAI
import json
import time
import ast
import re
import os
from typing import Dict, Any, Tuple, Optional
import concurrent.futures

class DeepSeekAnalyzer:
    def __init__(self, api_key: str, bailian_api_key: str = None, use_model_extraction: bool = True):
        """
        初始化DeepSeek分析器
        
        Args:
            api_key: DeepSeek API密钥
            bailian_api_key: 百炼API密钥，用于调用DeepSeek V3
            use_model_extraction: 是否使用模型进行CWE提取，默认为True
        """
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        
        # 处理百炼API异常情况
        if bailian_api_key and bailian_api_key != "your_bailian_api_key":
            try:
                self.client_v3 = OpenAI(
                    api_key=bailian_api_key,
                    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
                )
                self.use_bailian_api = True
            except Exception as e:
                print(f"百炼API初始化失败，使用DeepSeek API替代: {e}")
                self.client_v3 = OpenAI(
                    api_key=api_key,
                    base_url="https://api.deepseek.com"
                )
                self.use_bailian_api = False
        else:
            print("百炼API配置异常，使用DeepSeek API替代")
            self.client_v3 = OpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com"
            )
            self.use_bailian_api = False
        
        self.use_model_extraction = use_model_extraction
    
    def analyze_function(self, func_body: str) -> Tuple[str, str]:
        """
        调用DeepSeek R1模型分析函数漏洞
        
        Args:
            func_body: 函数体代码
            
        Returns:
            tuple: (思维链reasoning_content, 正式输出结果content)
        """
        prompt = f"""
            检查代码中是否存在安全漏洞，深度思考时请简化深度思考的输出，结果输出要求：
            1、若发现漏洞，结果中提供相关的 CWE（Common Weakness Enumeration）编号、风险描述和相关的代码。
            2、否则结果中输出无漏洞。 
            3、不要生成修复建议等无关内容。
            以下是待检测的代码：
            {func_body}
        """

        messages = [
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.client.chat.completions.create(
                model="deepseek-reasoner",
                messages=messages,
                # response_format={
                #     'type': 'json_object'
                # },
            )
            
            # 获取思维链和正式输出
            reasoning_content = response.choices[0].message.reasoning_content or ""
            content = response.choices[0].message.content or ""
            
            return reasoning_content, content
            
        except Exception as e:
            print(f"API调用失败: {e}")
            return f"API调用失败: {e}", ""
    
    def analyze_vulnerability_focused(self, func_body: str, original_cwe: str, changed_statements: str) -> Tuple[str, str, str]:
        """
        新增三列分析结果：prompt7, ds_thinking7, ds_response7
        
        Args:
            func_body: 函数体代码
            cwe_info: CWE漏洞信息
            changed_statements: 可能存在漏洞的代码语句
            
        Returns:
            tuple: (prompt内容, 思维链reasoning_content, 正式输出结果content)
        """
        cwe_info = format_cwe_info(original_cwe)
        prompt = f"""你是一名代码漏洞分析专家，现在你需要帮我分析一段存在漏洞的代码，代码具体内容如下：
{func_body}

漏洞类型为：
{cwe_info}

对应的漏洞行和代码语句为：
{changed_statements}

**【注意事项】**：
1. 这里给出的漏洞行不一定准确，因此你只需要关注具体漏洞语句的内容。
2. 原始代码中明确存在{cwe_info}漏洞，因此请仔细分析上述代码和我提供的漏洞代码区间信息，不要输出无漏洞或者其他类型的CWE漏洞分析结果。
3. 请给出不超过500字的精简漏洞分析过程，不要输出修复建议之类的无关内容。"""

        messages = [
            {"role": "user", "content": prompt}
        ]
        
        last_error = None
        
        # 增加重试机制，最多重试3次
        for attempt in range(3):
            try:
                print(f"专门漏洞分析调用尝试第 {attempt + 1}/3 次...")
                
                response = self.client.chat.completions.create(
                    model="deepseek-reasoner",
                    messages=messages,
                )
                
                # 获取思维链和正式输出
                reasoning_content = response.choices[0].message.reasoning_content or ""
                content = response.choices[0].message.content or ""

                # 验证生成的内容是否包含正确的CWE
                extracted_cwe = self.extract_cwe_from_output(content)
                is_correct = self.check_cwe_correctness(original_cwe, extracted_cwe)
                
                if is_correct == '√':
                    print("生成的分析结果验证通过")
                    return prompt, reasoning_content, content
                else:
                    print(f"第 {attempt + 1} 次尝试验证失败，期望CWE: {cwe_info}，实际提取: {extracted_cwe}")
                    if attempt < 2:  # 不是最后一次重试
                        continue
                    else:
                        # 最后一次重试也失败了，返回结果（不进行验证）
                        print("所有重试均验证失败，返回最后一次分析结果")
                        return prompt, reasoning_content, content
                
            except Exception as e:
                print(f"第 {attempt + 1} 次专门漏洞分析API调用失败: {e}")
                last_error = e
                if attempt < 2:  # 不是最后一次重试
                    time.sleep(1)
                    continue
                else:
                    # 最后一次重试也失败了
                    return prompt, f"API调用失败: {e}", ""
        
        # 如果所有重试都失败了（理论上不会执行到这里）
        return prompt, f"API调用失败: {last_error}", ""
    
    def analyze_with_correct_cwe(self, func_body: str, cwe_info: str, cve_info: str = "", changed_statements: str = "") -> Tuple[str, str]:
        """
        使用正确的CWE信息重新分析函数漏洞
        
        Args:
            func_body: 函数体代码
            cwe_info: 正确的CWE信息
            cve_info: CVE信息
            changed_statements: 可能存在漏洞代码的区间
            
        Returns:
            tuple: (思维链reasoning_content, 正式输出结果content)
        """
        # 构建CVE信息部分
        cve_section = f"漏洞相关CVE编号：{cve_info}" if cve_info else ""
        
        prompt = f"""
{func_body}
上述代码存在{cwe_info}漏洞，请仔细分析这段程序，找出存在漏洞的代码并分析其潜在的风险（注意不要生成修复建议等无关内容）。
可能存在漏洞的代码区间：{changed_statements}
{cve_section}

**注意：原始代码中明确存在{cwe_info}漏洞，因此请仔细分析上述代码和我提供的漏洞代码区间信息，不要输出无漏洞或者其他类型的CWE漏洞分析结果。**

以下是一个输出示例（仅作参考，你可以自行补充你觉得合适的内容）：
空指针解引用风险（CWE-476）​
问题代码​：
cancel_work_sync(&nxpdev->tx_work);  // 工作队列取消
kfree_skb(nxpdev->rx_skb);          // SKB缓冲区释放
风险描述​：
当nxpdev为NULL时，cancel_work_sync()和kfree_skb()调用将导致内核空指针解引用（kernel NULL pointer dereference）。虽然hci_get_drvdata(hdev)通常应返回有效指针，但在错误处理路径或异常状态下可能返回NULL。
"""

        messages = [
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.client.chat.completions.create(
                model="deepseek-reasoner",
                messages=messages,
            )
            
            # 获取思维链和正式输出
            reasoning_content = response.choices[0].message.reasoning_content or ""
            content = response.choices[0].message.content or ""
            
            return reasoning_content, content
            
        except Exception as e:
            print(f"二次API调用失败: {e}")
            return f"二次API调用失败: {e}", ""
    
    def extract_cwe_with_model(self, ds_output: str, max_retries: int = 3) -> list:
        """
        使用DeepSeek V3模型从输出结果中提取CWE编号（带重试机制）
        
        Args:
            ds_output: 原始分析输出结果
            max_retries: 最大重试次数，默认为3次
            
        Returns:
            list: CWE编号列表
        """
        if not ds_output:
            return []
        
        prompt = f"""{ds_output}
这是一段代码漏洞检测的判断结果，请你帮我判断一下这段文本是否认为原始代码中存在漏洞，如果存在，请返回所有不同的 CWE 编号，如果不存在，则输出"无漏洞"。

你需要返回json格式的输出，具体格式要求如下：
{{
"result": 你的判断结果
}}
注意，判断结果只能为"无漏洞"或者["CWE-XXX"]格式的字符串数组，不要出现其他类型格式。**请确保返回有效的JSON格式，不要返回空内容。**"""

        messages = [
            {"role": "user", "content": prompt}
        ]
        
        for attempt in range(max_retries):
            try:
                print(f"CWE提取尝试第 {attempt + 1}/{max_retries} 次...")
                
                # 根据是否使用百炼API决定模型选择
                if self.use_bailian_api:
                    model_name = "deepseek-v3"
                else:
                    model_name = "deepseek-chat"  # 使用DeepSeek API时的模型名
                
                response = self.client_v3.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    response_format={
                        'type': 'json_object'
                    },
                )
                
                content = response.choices[0].message.content or ""
                
                # 检查是否返回空内容
                if not content.strip():
                    print(f"第 {attempt + 1} 次尝试返回空内容，准备重试...")
                    if attempt < max_retries - 1:
                        time.sleep(1)  # 短暂等待后重试
                        continue
                    else:
                        print("所有重试均返回空内容，使用正则表达式回退方案")
                        return []
                
                # 解析JSON响应
                try:
                    # 清理可能的markdown代码块标记
                    cleaned_content = content.strip()
                    if cleaned_content.startswith('```json'):
                        cleaned_content = cleaned_content[7:]  # 去掉开头的```json
                    if cleaned_content.endswith('```'):
                        cleaned_content = cleaned_content[:-3]  # 去掉结尾的```
                    cleaned_content = cleaned_content.strip()
                    
                    data = json.loads(cleaned_content)
                    result = data.get('result', '')
                    
                    # 检查结果是否为空或无效
                    if result == '' or result is None:
                        print(f"第 {attempt + 1} 次尝试返回空结果，准备重试...")
                        if attempt < max_retries - 1:
                            time.sleep(1)
                            continue
                        else:
                            print("所有重试均返回空结果")
                            return []
                    
                    if result == '无漏洞':
                        print(f"模型判断：无漏洞")
                        return []
                    elif isinstance(result, list):
                        # 验证列表中的元素都是CWE格式
                        cwe_list = []
                        for item in result:
                            if isinstance(item, str) and item.startswith('CWE-'):
                                cwe_list.append(item)
                        
                        # 如果提取的CWE列表为空，尝试重试
                        if not cwe_list and attempt < max_retries - 1:
                            print(f"第 {attempt + 1} 次尝试未提取到有效CWE，准备重试...")
                            time.sleep(1)
                            continue
                        
                        print(f"模型提取CWE: {cwe_list}")
                        return list(set(cwe_list))  # 去重
                    else:
                        print(f"第 {attempt + 1} 次尝试返回不期望的格式: {result}")
                        if attempt < max_retries - 1:
                            time.sleep(1)
                            continue
                        else:
                            print("所有重试均返回不期望的格式")
                            return []
                        
                except json.JSONDecodeError as e:
                    print(f"第 {attempt + 1} 次尝试JSON解析失败: {e}, 原始内容: {content}")
                    if attempt < max_retries - 1:
                        time.sleep(1)
                        continue
                    else:
                        print("所有重试均出现JSON解析错误")
                        return []
                
            except Exception as e:
                print(f"第 {attempt + 1} 次尝试API调用失败: {e}")
                if attempt < max_retries - 1:
                    print(f"等待2秒后进行重试...")
                    time.sleep(2)
                    continue
                else:
                    print("所有重试均失败")
                    return []
        
        # 如果所有重试都失败了，返回空列表
        print(f"经过 {max_retries} 次重试后仍然失败，返回空列表")
        return []
    
    def extract_cwe_from_output(self, output: str) -> list:
        """
        从输出结果中提取CWE编号（优先使用模型提取，失败则回退到正则表达式）
        
        Args:
            output: 分析输出结果
            
        Returns:
            list: CWE编号列表
        """
        if not output:
            return []
        
        # 根据配置决定是否使用模型提取CWE
        if self.use_model_extraction:
            try:
                model_result = self.extract_cwe_with_model(output)
                print(f"使用模型提取CWE成功: {model_result}")
                return model_result
            except Exception as e:
                print(f"模型提取CWE失败，回退到正则表达式方法: {e}")
        
        # 使用正则表达式方法
        print("使用正则表达式方法提取CWE")
        
        # 首先检查是否明确表示无漏洞
        no_vuln_patterns = [
            r'无漏洞',
            r'未发现.*?漏洞',
            r'不存在.*?漏洞',
            r'没有.*?漏洞',
            r'结论.*?无漏洞',
            r'结论.*?未发现.*?漏洞',
            r'结论.*?不存在.*?漏洞'
        ]
        
        for pattern in no_vuln_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                print(f"正则检测到无漏洞结论，忽略文本中的CWE编号")
                return []
        
        try:
            # 尝试解析JSON
            data = json.loads(output)
            analysis_result = data.get('分析结果', '')
            
            if analysis_result == '无漏洞':
                return []
            
            # 如果是字符串列表
            if isinstance(analysis_result, list):
                # 添加去重逻辑
                return list({cwe for cwe in analysis_result if cwe.startswith('CWE-')})
            
            # 如果是单个字符串
            if isinstance(analysis_result, str) and analysis_result.startswith('CWE-'):
                return [analysis_result]
                
        except json.JSONDecodeError:
            # 如果JSON解析失败，尝试正则表达式提取并去重
            cwe_pattern = r'CWE-\d+'
            extracted_cwes = list(set(re.findall(cwe_pattern, output)))
            
            # 再次检查是否有明确的无漏洞结论
            # 如果有CWE编号但结论是无漏洞，则返回空列表
            if extracted_cwes:
                for pattern in no_vuln_patterns:
                    if re.search(pattern, output, re.IGNORECASE):
                        print(f"虽然提到了CWE编号{extracted_cwes}，但结论是无漏洞")
                        return []
            
            print(f"正则表达式提取CWE: {extracted_cwes}")
            return extracted_cwes
        
        return []
    
    def check_cwe_correctness(self, original_cwe: str, extracted_cwe: list) -> str:
        """
        检查CWE编号是否正确
        
        Args:
            original_cwe: 原始CWE列内容，格式如 "['CWE-200']"
            extracted_cwe: 从分析结果中提取的CWE列表
            
        Returns:
            str: '√' 如果匹配，'×' 如果不匹配
        """
        try:
            # 解析原始CWE列表
            if pd.isna(original_cwe) or original_cwe == '':
                original_list = []
            else:
                # 处理字符串格式的列表
                original_list = ast.literal_eval(original_cwe)
                if not isinstance(original_list, list):
                    original_list = [original_list]
        except:
            original_list = []
        
        # 提取CWE编号（去掉前缀等）
        original_cwe_numbers = set()
        for cwe in original_list:
            if isinstance(cwe, str) and cwe.startswith('CWE-'):
                original_cwe_numbers.add(cwe)
        
        extracted_cwe_numbers = set(extracted_cwe)
        
        # 检查原始信息是否完全被包含
        # return '√' if original_cwe_numbers.intersection(extracted_cwe_numbers) else '×'
        return '√' if all(cwe in extracted_cwe_numbers for cwe in original_cwe_numbers) else '×'
    
    def reduce_thinking_content(self, ds_think_content: str) -> str:
        """
        对ds_think内容进行删减，保持在600-1000字之间
        
        Args:
            ds_think_content: 原始的思维链内容
            
        Returns:
            str: 删减后的思维链内容
        """
        if not ds_think_content or len(ds_think_content) <= 1000:
            if len(ds_think_content) >= 600:
                return ds_think_content
        
        # example = "我们分析给定的代码：static void willRemoveChildren(ContainerNode* container) 主要功能：移除容器节点的所有子节点。 关键点：先获取子节点列表快照，再遍历该快照。这避免了因移除节点导致容器结构变化而引起的迭代器失效问题。但我们需关注在遍历过程中，子节点被通知将要被移除（notifyMutationObserversNodeWillDetach）并触发事件（dispatchChildRemovalEvents）时，是否可能修改DOM树。 在回调中移除其他节点可能影响操作，但遍历的是快照列表，因此容器当前子节点变化不影响当前操作。然而，如果回调删除当前处理的子节点，后续操作可能访问已释放内存。 更严重的漏洞在于：通知观察者时，脚本可能对DOM进行任意修改，包括移除容器节点。如果容器节点被销毁，后续操作（如mutation.willRemoveChild(child)和ChildFrameDisconnector）将使用悬垂指针，导致UAF漏洞。 相关代码： for (...) { child->notifyMutationObserversNodeWillDetach(); // 可能触发回调，销毁container dispatchChildRemovalEvents(child); // 也存在风险 } ChildFrameDisconnector(container).disconnect(...); // 使用可能已被释放的container 结论：存在CWE-416（Use After Free）漏洞。当通知突变观察者节点将要被移除时，观察者的回调可能会销毁容器节点，导致后续操作使用已被释放的内存。 风险描述：在移除容器节点的子节点过程中，通知突变观察者可能导致容器节点被销毁，后续操作（包括循环迭代和ChildFrameDisconnector）使用已释放的container指针，引发安全漏洞。"
        format = """我们正在分析xxx代码片段/程序，需要检查可能的安全漏洞。

代码功能：<待填充>

关键点：<待填充>

潜在漏洞分析：<待填充>

结论：存在xx漏洞（给出CWE编号）/无漏洞
"""
        prompt = f"""{ds_think_content}\n---------------------------------------------------------\n任务要求：\n删减这段文字内容以减少其字数（切记不要添加或者总结任何内容，尽量保证原始文本的排版不变，你的任务只是做单纯的文字删减和必要的文字衔接）。 注意事项： 1. 请严格按照思维链的格式输出，体现出原始思维链中的思考过程（重点在于第一人称与探索反思），不要写成总结型内容。 2. 保证删减之后的文字连贯，不要出现生硬的截断内容，确保生成文本的结构完整性。 3. 保留核心分析内容，重复以及不重要的部分可以删除和丢弃。 4. 删减之后确保不少于600字且不要超过1000个字！！！（这个很重要，一定要遵守）。\n以下是一份输出的参考格式（仅供参考，你可以自行补充你觉得合适的内容）：\n{format}"""
        
        messages = [
            {"role": "user", "content": prompt}
        ]
        
        max_attempts = 2  # 最大重试次数
        reduced_content = ""
        
        for attempt in range(max_attempts):
            try:
                response = self.client.chat.completions.create(
                    model="deepseek-reasoner",
                    messages=messages,
                )
                
                reduced_content = response.choices[0].message.content or ""
                
                # 检查字数是否符合要求
                char_count = len(reduced_content)
                if 600 <= char_count <= 1000:
                    print(f"删减成功，字数: {char_count}")
                    return reduced_content
                else:
                    print(f"第 {attempt + 1} 次删减字数不符合要求: {char_count} 字，要求600-1000字")
                    if attempt < max_attempts - 1:
                        # 调整prompt以提醒字数要求
                        if char_count < 600:
                            prompt = f"""原始思维链：\n{ds_think_content}\n删减过后的思维链：\n{reduced_content}\n---------------------------------------------------------\n任务要求：\n删减这段文字内容以减少其字数（切记不要添加或者总结任何内容，尽量保证原始文本的排版不变，你的任务只是做单纯的文字删减和必要的文字衔接）。 注意事项： 1. 请严格按照思维链的格式输出，体现出原始思维链中的思考过程（重点在于第一人称与探索反思），不要写成总结型内容。 2. 保证删减之后的文字连贯，不要出现生硬的截断内容，确保生成文本的结构完整性。 3. 保留核心分析内容，重复以及不重要的部分可以删除和丢弃。 4. 删减之后确保不少于600字且不要超过1000个字！！！**当前删减过度了，需要保留更多内容以达到至少600字**。\n以下是一份输出的参考格式（仅供参考，你可以自行补充你觉得合适的内容）：\n{format}"""
                        else:
                            prompt = f"""原始思维链：\n{ds_think_content}\n删减过后的思维链：\n{reduced_content}\n---------------------------------------------------------\n任务要求：\n删减这段文字内容以减少其字数（切记不要添加或者总结任何内容，尽量保证原始文本的排版不变，你的任务只是做单纯的文字删减和必要的文字衔接）。 注意事项： 1. 请严格按照思维链的格式输出，体现出原始思维链中的思考过程（重点在于第一人称与探索反思），不要写成总结型内容。 2. 保证删减之后的文字连贯，不要出现生硬的截断内容，确保生成文本的结构完整性。 3. 保留核心分析内容，重复以及不重要的部分可以删除和丢弃。 4. 删减之后确保不少于600字且不要超过1000个字！！！**当前删减不够，需要进一步删减以控制在1000字以内**。\n以下是一份输出的参考格式（仅供参考，你可以自行补充你觉得合适的内容）：\n{format}"""
                        messages = [{"role": "user", "content": prompt}]
                        time.sleep(1)  # 添加延迟
                
            except Exception as e:
                print(f"删减API调用失败（第 {attempt + 1} 次）: {e}")
                if attempt == max_attempts - 1:
                    return f"删减失败: {e}"
                time.sleep(5)
        
        return reduced_content

    def generate_correct_output_with_retry(self, func_body: str, original_cwe: str, cve_info: str, changed_statements: str) -> tuple:
        """
        生成correct_output并进行验证，如果需要则重试2次
        
        Args:
            func_body: 函数体代码
            original_cwe: 原始CWE信息
            cve_info: CVE信息
            changed_statements: 可能存在漏洞代码的区间
            
        Returns:
            tuple: (correct_output内容, 是否需要人工校正)
        """
        cwe_info = format_cwe_info(original_cwe)
        if not cwe_info:
            return '', False
        
        # 检查是否为"NVD-CWE-noinfo"，如果是则不需要验证
        is_no_info = "NVD-CWE-noinfo" in original_cwe or "noinfo" in original_cwe.lower()
        
        # 第一次生成
        _, correct_content = self.analyze_with_correct_cwe(func_body, cwe_info, cve_info, changed_statements)
        
        # 如果是noinfo或者验证通过，直接返回
        if is_no_info:
            print("CWE为noinfo类型，无需验证，直接使用生成结果")
            return correct_content, False
        
        # 验证生成的内容是否包含正确的CWE
        extracted_cwe = self.extract_cwe_from_output(correct_content)
        is_correct = self.check_cwe_correctness(original_cwe, extracted_cwe)
        
        if is_correct == '√':
            print("生成的correct_output验证通过")
            return correct_content, False
        else:
            # 如果验证失败，则重试2次
            for retry_cnt in range(2):
                print(f"生成的correct_output验证失败，重试第{retry_cnt+1}次...")
                _, retry_content = self.analyze_with_correct_cwe(func_body, cwe_info, cve_info, changed_statements)
                
                extracted_cwe = self.extract_cwe_from_output(retry_content)
                is_correct = self.check_cwe_correctness(original_cwe, extracted_cwe)
                
                if is_correct == '√':
                    print("重试完成")
                    return retry_content, False
                else:
                    print(f"第{retry_cnt+1}次重试失败")
            
            # 所有重试都失败了，需要人工校正
            print("生成correct_output失败，需要人工校正")
            return retry_content, True

def get_file_extension(file_path: str) -> str:
    return os.path.splitext(file_path)[1].lower()

def read_file(file_path: str, **kwargs) -> pd.DataFrame:
    """
    根据文件扩展名读取文件
    
    Args:
        file_path: 文件路径
        **kwargs: 传递给pandas读取函数的额外参数
        
    Returns:
        pd.DataFrame: 读取的数据框
    """
    ext = get_file_extension(file_path)
    
    if ext == '.csv':
        # 默认参数，可以被kwargs覆盖
        default_params = {'encoding': 'utf-8'}
        default_params.update(kwargs)
        return pd.read_csv(file_path, **default_params)
    elif ext in ['.xlsx', '.xls']:
        # 默认参数，可以被kwargs覆盖
        default_params = {'engine': 'openpyxl' if ext == '.xlsx' else 'xlrd'}
        default_params.update(kwargs)
        return pd.read_excel(file_path, **default_params)
    else:
        raise ValueError(f"不支持的文件格式: {ext}。支持的格式: .csv, .xlsx, .xls")

def save_file(df: pd.DataFrame, file_path: str, **kwargs) -> None:
    """
    根据文件扩展名保存文件
    
    Args:
        df: 要保存的数据框
        file_path: 保存路径
        **kwargs: 传递给pandas保存函数的额外参数
    """
    ext = get_file_extension(file_path)
    
    if ext == '.csv':
        # 解决CSV截断问题：设置CSV的最大字段大小
        import csv
        csv.field_size_limit(1000000)  # 设置为1MB
        
        default_params = {
            'index': False, 
            'encoding': 'utf-8',
            'quoting': csv.QUOTE_ALL,  # 所有字段都加引号，防止长文本截断
            'escapechar': '\\'  # 设置转义字符
        }
        default_params.update(kwargs)
        df.to_csv(file_path, **default_params)
    elif ext in ['.xlsx', '.xls']:
        # 默认参数，可以被kwargs覆盖
        default_params = {'index': False, 'engine': 'openpyxl'}
        default_params.update(kwargs)
        df.to_excel(file_path, **default_params)
    else:
        raise ValueError(f"不支持的文件格式: {ext}。支持的格式: .csv, .xlsx, .xls")

def format_cwe_info(cwe_str: str) -> str:
    """
    格式化CWE信息，将字符串列表转换为可读格式
    
    Args:
        cwe_str: CWE列的字符串，如 "['CWE-200']"
        
    Returns:
        str: 格式化后的CWE信息
    """
    try:
        if pd.isna(cwe_str) or cwe_str == '':
            return ""
        
        # 解析CWE列表
        cwe_list = ast.literal_eval(cwe_str)
        if not isinstance(cwe_list, list):
            cwe_list = [cwe_list]
        
        # 格式化CWE信息
        if len(cwe_list) == 1:
            return cwe_list[0]
        else:
            return ", ".join(cwe_list)
    except:
        # 如果解析失败，直接返回原字符串
        return str(cwe_str)

def format_cwe_result(cwe_list: list) -> str:
    """
    格式化CWE结果用于ds_result列
    
    Args:
        cwe_list: CWE编号列表
        
    Returns:
        str: 格式化后的结果，空列表返回"无漏洞"
    """
    if not cwe_list:
        return "无漏洞"
    elif len(cwe_list) == 1:
        return cwe_list[0]
    else:
        return ", ".join(cwe_list)

def post_process_missing_rows(output_file: str, api_key: str, bailian_api_key: str = None, max_workers: int = 5, use_model_extraction: bool = True, only_new_fields: bool = False):
    """
    后处理：检查输出文件中的缺失行并重新处理
    
    Args:
        output_file: 输出文件路径
        api_key: DeepSeek API密钥
        bailian_api_key: 百炼API密钥，用于调用DeepSeek V3
        max_workers: 最大线程数
        use_model_extraction: 是否使用模型进行CWE提取
        only_new_fields: 是否只处理新增的三个字段（prompt7, ds_thinking7, ds_response7）
    """
    print(f"\n开始后处理检查: {output_file}")
    
    # 读取输出文件
    df = read_file(output_file)
    
    # 在增量更新模式下，记录原始列名并过滤无关列
    if only_new_fields:
        # 过滤掉pandas自动生成的Unnamed列
        original_columns = [col for col in df.columns if not col.startswith('Unnamed')]
        df = df[original_columns]  # 只保留有意义的列
        print(f"增量模式：保留原始列 {len(original_columns)} 个")
        
        # 确保新增的三个字段列存在
        for col in ['prompt7', 'ds_thinking7', 'ds_response7']:
            if col not in df.columns:
                df[col] = ''  # 只添加缺失的新字段列
    
    # 根据参数决定检查哪些列
    if only_new_fields:
        required_columns = ['prompt7', 'ds_thinking7', 'ds_response7']
        print("只检查新增的三个字段: prompt7, ds_thinking7, ds_response7")
    else:
        # 检查需要的十个列（新增manual_review_needed, prompt7, ds_thinking7, ds_response7）
        required_columns = ['ds_think', 'ds_output', 'ds_result', 'is_correct', 'correct_output', 'ds_think_reduced', 'manual_review_needed', 'prompt7', 'ds_thinking7', 'ds_response7']
        print("检查所有字段")
    
    # 找出有缺失值的行
    missing_rows = []
    for idx, row in df.iterrows():
        is_missing = False
        for col in required_columns:
            if col not in df.columns or pd.isna(row[col]) or row[col] == '' or str(row[col]).strip() == '':
                is_missing = True
                break
        if is_missing:
            missing_rows.append(idx)
    
    if not missing_rows:
        print("所有行都已完整处理，无需后处理")
        return
    
    print(f"发现 {len(missing_rows)} 行需要重新处理: {missing_rows}")
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer(api_key, bailian_api_key, use_model_extraction)
    
    def process_missing_row(idx):
        """处理单个缺失行"""
        row = df.loc[idx].copy()
        try:
            print(f"重新处理第 {idx} 行...")
            
            func_body = row['func_body']
            if pd.isna(func_body) or func_body == '':
                if only_new_fields:
                    # 只处理新增字段
                    row['prompt7'] = ''
                    row['ds_thinking7'] = '函数体为空'
                    row['ds_response7'] = ''
                else:
                    # 处理所有字段
                    row['ds_think'] = '函数体为空'
                    row['ds_output'] = ''
                    row['ds_result'] = '无漏洞'
                    row['is_correct'] = '×'
                    row['correct_output'] = ''
                    row['ds_think_reduced'] = ''
                    row['manual_review_needed'] = '是'  # 函数体为空需要人工校正
                    # 新增字段的处理
                    row['prompt7'] = ''
                    row['ds_thinking7'] = '函数体为空'
                    row['ds_response7'] = ''
                return idx, row
            
            # 根据参数决定是否进行原有的分析处理
            if not only_new_fields:
                # 调用API分析
                reasoning_content, content = analyzer.analyze_function(func_body)
                
                # 存储结果
                row['ds_think'] = reasoning_content
                row['ds_output'] = content
                
                # 提取CWE并检查正确性
                extracted_cwe = analyzer.extract_cwe_from_output(content)
                row['ds_result'] = format_cwe_result(extracted_cwe)
                
                original_cwe = row['cwe_list']
                is_correct = analyzer.check_cwe_correctness(original_cwe, extracted_cwe)
                row['is_correct'] = is_correct
                
                # 根据正确性处理correct_output
                if is_correct == '√':
                    row['correct_output'] = content
                    row['manual_review_needed'] = '否'
                    print(f"第 {idx} 行处理完成 - 判断正确")
                else:
                    cwe_info = format_cwe_info(original_cwe)
                    if cwe_info:
                        print(f"第 {idx} 行判断错误，使用正确CWE重新分析: {cwe_info}")
                        changed_statements = row.get('changed_statements', '')
                        cve_list = row.get('cve_list', '')
                        correct_content, manual_review_needed = analyzer.generate_correct_output_with_retry(func_body, original_cwe, cve_list, changed_statements)
                        row['correct_output'] = correct_content
                        row['manual_review_needed'] = '是' if manual_review_needed else '否'
                        if manual_review_needed:
                            print(f"第 {idx} 行二次分析完成，但需要人工校正")
                        else:
                            print(f"第 {idx} 行二次分析完成")
                    else:
                        row['correct_output'] = ''
                        row['manual_review_needed'] = '是'  # 无有效CWE信息需要人工校正
                        print(f"第 {idx} 行无有效CWE信息，需要人工校正")
                
                # 对ds_think进行删减处理
                if reasoning_content:
                    print(f"第 {idx} 行正在删减思维链内容，原长度: {len(reasoning_content)} 字符")
                    reduced_thinking = analyzer.reduce_thinking_content(reasoning_content)
                    row['ds_think_reduced'] = reduced_thinking
                    print(f"第 {idx} 行思维链删减完成，新长度: {len(reduced_thinking)} 字符")
                else:
                    row['ds_think_reduced'] = ''
            
            # 新增功能：生成prompt7, ds_thinking7, ds_response7三个字段
            try:
                # 获取必要的信息
                original_cwe = row['cwe_list']
                cwe_info = format_cwe_info(original_cwe)  # 需要格式化CWE信息用于判断
                changed_statements = row.get('changed_statements', '')
                
                if cwe_info:
                    print(f"第 {idx} 行正在生成专门漏洞分析...")
                    prompt7, ds_thinking7, ds_response7 = analyzer.analyze_vulnerability_focused(func_body, original_cwe, changed_statements)
                    
                    row['prompt7'] = prompt7
                    row['ds_thinking7'] = ds_thinking7
                    row['ds_response7'] = ds_response7
                    
                    print(f"第 {idx} 行专门漏洞分析完成")
                else:
                    print(f"第 {idx} 行无有效CWE信息，跳过专门漏洞分析")
                    row['prompt7'] = ''
                    row['ds_thinking7'] = ''
                    row['ds_response7'] = ''
                    
            except Exception as e:
                print(f"第 {idx} 行专门漏洞分析失败: {e}")
                row['prompt7'] = ''
                row['ds_thinking7'] = f'分析失败: {e}'
                row['ds_response7'] = ''
            
            print(f"第 {idx} 行重新处理完成")
            time.sleep(1)  # 添加延迟避免API限流
            return idx, row
            
        except Exception as e:
            print(f"重新处理第 {idx} 行时出错: {e}")
            if only_new_fields:
                # 只处理新增字段的错误
                row['prompt7'] = ''
                row['ds_thinking7'] = f'处理错误: {e}'
                row['ds_response7'] = ''
            else:
                # 处理所有字段的错误
                row['ds_think'] = f'处理错误: {e}'
                row['ds_output'] = ''
                row['ds_result'] = '处理错误'
                row['is_correct'] = '×'
                row['correct_output'] = ''
                row['ds_think_reduced'] = ''
                row['manual_review_needed'] = '是'  # 处理错误需要人工校正
                # 新增字段的错误处理
                row['prompt7'] = ''
                row['ds_thinking7'] = f'处理错误: {e}'
                row['ds_response7'] = ''
            return idx, row
    
    # 多线程处理缺失行
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_missing_row, idx) for idx in missing_rows]
        
        for future in concurrent.futures.as_completed(futures):
            idx, updated_row = future.result()
            # 更新原DataFrame
            if only_new_fields:
                # 增量更新模式：只更新新增的三个字段
                for col in ['prompt7', 'ds_thinking7', 'ds_response7']:
                    if col in updated_row:
                        df.at[idx, col] = updated_row[col]
            else:
                # 完整处理模式：更新所有相关字段
                for col in required_columns:
                    df.at[idx, col] = updated_row[col]
    
    # 保存更新后的文件
    if only_new_fields:
        # 增量更新模式：只保存原始列+新增的三个字段
        save_columns = original_columns + ['prompt7', 'ds_thinking7', 'ds_response7']
        # 去重并保持原有顺序
        save_columns = list(dict.fromkeys(save_columns))  
        df_to_save = df[save_columns]
        save_file(df_to_save, output_file)
        print(f"增量更新完成！已更新 {len(missing_rows)} 行的新增字段，保存 {len(save_columns)} 列到 {output_file}")
    else:
        # 完整处理模式：保存所有列
        save_file(df, output_file)
        print(f"后处理完成！已更新 {len(missing_rows)} 行，结果保存到 {output_file}")

def process_file(input_file: str, output_file: str, api_key: str, bailian_api_key: str = None,
                sheet_name: str = None, max_workers: int=5, use_model_extraction: bool = True, only_new_fields: bool = False, **file_kwargs):
    """
    处理文件（支持CSV和XLSX）
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        api_key: DeepSeek API密钥
        bailian_api_key: 百炼API密钥，用于调用DeepSeek V3
        sheet_name: Excel工作表名称（仅对xlsx文件有效）
        max_workers: 最大线程数
        use_model_extraction: 是否使用模型进行CWE提取
        only_new_fields: 是否只处理新增的三个字段（prompt7, ds_thinking7, ds_response7）
        **file_kwargs: 传递给文件读取函数的额外参数
    """
    # 读取文件
    read_kwargs = file_kwargs.copy()
    if sheet_name and get_file_extension(input_file) in ['.xlsx', '.xls']:
        read_kwargs['sheet_name'] = sheet_name
    
    print(f"正在读取文件: {input_file}")
    if sheet_name:
        print(f"工作表: {sheet_name}")
    
    df = read_file(input_file, **read_kwargs)
    
    # 检查必需的列
    required_columns = ['func_body', 'cwe_list']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"缺少必需的列: {missing_columns}")
    
    print(f"文件读取成功，共 {len(df)} 行数据")
    print(f"列名: {list(df.columns)}")
    
    # 预检查：检查必要列是否完整
    required_input_columns = ['func_body', 'changed_statements', 'cve_list', 'cwe_list']
    print(f"开始预检查必要列: {required_input_columns}")
    
    valid_rows = []
    invalid_rows = []
    
    for idx, row in df.iterrows():
        is_valid = True
        missing_info = []
        
        for col in required_input_columns:
            if col not in df.columns:
                is_valid = False
                missing_info.append(f"缺少列'{col}'")
            elif pd.isna(row[col]) or str(row[col]).strip() == '':
                is_valid = False
                missing_info.append(f"列'{col}'为空")
        
        if is_valid:
            valid_rows.append(idx)
        else:
            invalid_row = row.copy()
            invalid_row['skip_reason'] = "; ".join(missing_info)
            invalid_rows.append(invalid_row)
    
    print(f"预检查完成: 有效行 {len(valid_rows)} 行, 无效行 {len(invalid_rows)} 行")
    
    # 保存无效行到 fail.csv
    if invalid_rows:
        fail_df = pd.DataFrame(invalid_rows)
        fail_file = output_file.replace('.csv', '_fail.csv').replace('.xlsx', '_fail.csv').replace('.xls', '_fail.csv')
        save_file(fail_df, fail_file)
        print(f"已将 {len(invalid_rows)} 行无效数据保存到: {fail_file}")
    
    # 只处理有效行
    if not valid_rows:
        print("没有有效的行可以处理！")
        return
    
    # 筛选出有效行进行处理
    df_valid = df.loc[valid_rows].copy()
    print(f"开始处理 {len(df_valid)} 条有效记录...")
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer(api_key, bailian_api_key, use_model_extraction)
    
    # 根据模式添加新列
    if only_new_fields:
        print("增量更新模式：只添加新增的三个字段")
        # 增量更新模式：只添加新增的三个字段
        if 'prompt7' not in df_valid.columns:
            df_valid['prompt7'] = ''
        if 'ds_thinking7' not in df_valid.columns:
            df_valid['ds_thinking7'] = ''
        if 'ds_response7' not in df_valid.columns:
            df_valid['ds_response7'] = ''
    else:
        print("完整处理模式：添加所有字段")
        # 完整处理模式：添加所有列（如果不存在）
        if 'ds_think' not in df_valid.columns:
            df_valid['ds_think'] = ''
        if 'ds_output' not in df_valid.columns:
            df_valid['ds_output'] = ''
        if 'ds_result' not in df_valid.columns:  # 新增列
            df_valid['ds_result'] = ''
        if 'is_correct' not in df_valid.columns:
            df_valid['is_correct'] = ''
        if 'correct_output' not in df_valid.columns:
            df_valid['correct_output'] = ''
        if 'ds_think_reduced' not in df_valid.columns:  # 新增删减后的思维链列
            df_valid['ds_think_reduced'] = ''
        if 'manual_review_needed' not in df_valid.columns:  # 新增人工校正标识列
            df_valid['manual_review_needed'] = ''
        # 新增的三个字段
        if 'prompt7' not in df_valid.columns:
            df_valid['prompt7'] = ''
        if 'ds_thinking7' not in df_valid.columns:
            df_valid['ds_thinking7'] = ''
        if 'ds_response7' not in df_valid.columns:
            df_valid['ds_response7'] = ''

    def get_ds_result(idx, row):
        # 先基于 row 复制一个新行出来
        new_row = row.copy()
        try:
            # 找到在原始df_valid中的实际位置
            actual_idx = df_valid.index.get_loc(idx)
            print(f"处理第 {actual_idx + 1}/{len(df_valid)} 条记录...")
            
            # 预检查已确保func_body不为空，此检查已不需要
            func_body = new_row['func_body']
            
            # 根据模式决定处理逻辑
            if only_new_fields:
                print(f"第 {actual_idx + 1} 条 - 增量更新模式：只处理新增字段")
                # 增量更新模式：跳过原有字段的处理，只处理新增的三个字段
                pass  # 跳过原有处理逻辑
            else:
                # 完整处理模式：检查是否已经存在所有必要字段，如果存在则跳过原有处理
                skip_original_processing = (
                    not pd.isna(new_row.get('ds_output', '')) and str(new_row.get('ds_output', '')).strip() != '' and
                    not pd.isna(new_row.get('ds_result', '')) and str(new_row.get('ds_result', '')).strip() != '' and
                    not pd.isna(new_row.get('ds_think', '')) and str(new_row.get('ds_think', '')).strip() != '' and
                    not pd.isna(new_row.get('correct_output', '')) and str(new_row.get('correct_output', '')).strip() != ''
                )
                
                # 根据条件判断是否跳过原有处理
                if skip_original_processing:
                    print(f"第 {actual_idx + 1} 条已存在所有必要字段，跳过原有处理")
                    reasoning_content = new_row.get('ds_think', '')
                    content = new_row.get('ds_output', '')
                    # extracted_cwe = analyzer.extract_cwe_from_output(content)
                    original_cwe = row['cwe_list']
                    is_correct = new_row.get('is_correct', '')
                else:
                    # 调用API分析
                    reasoning_content, content = analyzer.analyze_function(func_body)
                    
                    # 存储结果
                    new_row['ds_think'] = reasoning_content
                    new_row['ds_output'] = content
                    
                    # 提取CWE并检查正确性
                    extracted_cwe = analyzer.extract_cwe_from_output(content)
                    new_row['ds_result'] = format_cwe_result(extracted_cwe)  # 新增
                    
                    original_cwe = row['cwe_list']
                    is_correct = analyzer.check_cwe_correctness(original_cwe, extracted_cwe)
                    new_row['is_correct'] = is_correct
                    
                    # 根据正确性处理correct_output
                    if is_correct == '√':
                        # 如果正确，直接复制ds_output到correct_output
                        new_row['correct_output'] = content
                        new_row['manual_review_needed'] = '否'
                        print(f"第 {actual_idx + 1} 条处理完成 - 判断正确，直接复制输出")
                    else:
                        # 如果不正确，使用正确CWE重新调用API
                        cwe_info = format_cwe_info(original_cwe)
                        if cwe_info:
                            print(f"第 {actual_idx + 1} 条判断错误，使用正确CWE重新分析: {cwe_info}")
                            changed_statements = row.get('changed_statements', '')  # 获取changed_statements字段，默认为空
                            cve_list = row.get('cve_list', '')  # 获取cve_list字段，默认为空
                            correct_content, manual_review_needed = analyzer.generate_correct_output_with_retry(func_body, original_cwe, cve_list, changed_statements)
                            new_row['correct_output'] = correct_content
                            new_row['manual_review_needed'] = '是' if manual_review_needed else '否'
                            if manual_review_needed:
                                print(f"第 {actual_idx + 1} 条二次分析完成，但需要人工校正")
                            else:
                                print(f"第 {actual_idx + 1} 条二次分析完成")
                        else:
                            new_row['correct_output'] = ''
                            new_row['manual_review_needed'] = '是'  # 无有效CWE信息需要人工校正
                            print(f"第 {actual_idx + 1} 条无有效CWE信息，需要人工校正")
                    
                    # 对ds_think进行删减处理
                    if reasoning_content:
                        print(f"第 {actual_idx + 1} 条正在删减思维链内容，原长度: {len(reasoning_content)} 字符")
                        reduced_thinking = analyzer.reduce_thinking_content(reasoning_content)
                        new_row['ds_think_reduced'] = reduced_thinking
                        print(f"第 {actual_idx + 1} 条思维链删减完成，新长度: {len(reduced_thinking)} 字符")
                    else:
                        new_row['ds_think_reduced'] = ''
                    
                    print(f"第 {actual_idx + 1} 条原始CWE: {original_cwe}")
                    print(f"第 {actual_idx + 1} 条提取CWE: {extracted_cwe}")
                    print(f"第 {actual_idx + 1} 条DS结果: {new_row['ds_result']}")  # 新增
                    print(f"第 {actual_idx + 1} 条正确性: {is_correct}")
                    print(f"第 {actual_idx + 1} 条人工校正: {new_row['manual_review_needed']}")  # 新增
                    print(f"第 {actual_idx + 1} 条思维链长度: {len(reasoning_content)} 字符")
                    print(f"第 {actual_idx + 1} 条正式输出: {content[:100]}..." if len(content) > 100 else f"正式输出: {content}")
                    print("-" * 50)
            
            # 新增功能：生成prompt7, ds_thinking7, ds_response7三个字段（无论什么模式都要处理）
            try:
                # 获取必要的信息
                original_cwe = row['cwe_list']
                cwe_info = format_cwe_info(original_cwe)  # 需要格式化CWE信息用于判断
                changed_statements = row.get('changed_statements', '')
                
                if cwe_info:
                    print(f"第 {actual_idx + 1} 条正在生成专门漏洞分析...")
                    prompt7, ds_thinking7, ds_response7 = analyzer.analyze_vulnerability_focused(func_body, original_cwe, changed_statements)
                    
                    new_row['prompt7'] = prompt7
                    new_row['ds_thinking7'] = ds_thinking7
                    new_row['ds_response7'] = ds_response7
                    
                    print(f"第 {actual_idx + 1} 条专门漏洞分析完成")
                else:
                    print(f"第 {actual_idx + 1} 条无有效CWE信息，跳过专门漏洞分析")
                    new_row['prompt7'] = ''
                    new_row['ds_thinking7'] = ''
                    new_row['ds_response7'] = ''
                    
            except Exception as e:
                print(f"第 {actual_idx + 1} 条专门漏洞分析失败: {e}")
                new_row['prompt7'] = ''
                new_row['ds_thinking7'] = f'分析失败: {e}'
                new_row['ds_response7'] = ''
            
            # 添加延迟避免API限流
            time.sleep(1)
            return new_row
            
        except Exception as e:
            actual_idx = df_valid.index.get_loc(idx)
            print(f"处理第 {actual_idx + 1} 条记录时出错: {e}")
            
            # 根据模式处理错误
            if only_new_fields:
                # 增量模式：只设置新增字段的错误信息
                new_row['prompt7'] = ''
                new_row['ds_thinking7'] = f'处理错误: {e}'
                new_row['ds_response7'] = ''
            else:
                # 完整模式：设置所有字段的错误信息
                new_row['ds_think'] = f'处理错误: {e}'
                new_row['ds_output'] = ''
                new_row['ds_result'] = '处理错误'  # 新增
                new_row['is_correct'] = '×'
                new_row['correct_output'] = ''
                new_row['ds_think_reduced'] = ''  # 新增
                new_row['manual_review_needed'] = '是'  # 处理错误需要人工校正
                # 新增字段的错误处理
                new_row['prompt7'] = ''
                new_row['ds_thinking7'] = f'处理错误: {e}'
                new_row['ds_response7'] = ''
            return new_row
    
    # 多线程处理
    processed_rows = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        futures = {executor.submit(get_ds_result, idx, row): idx for idx, row in df_valid.iterrows()}
        # 收集结果，保持原始索引
        for future in concurrent.futures.as_completed(futures):
            original_idx = futures[future]
            new_row = future.result()
            processed_rows[original_idx] = new_row
    
    # 按原始索引顺序构建结果DataFrame
    new_df = pd.DataFrame([processed_rows[idx] for idx in sorted(processed_rows.keys())])
    
    # 根据模式决定保存的列
    if only_new_fields:
        # 增量更新模式：保存原有列 + 新增的三个字段
        # 智能过滤：排除空的Unnamed列，但保留有数据的Unnamed列
        original_columns = []
        for col in df.columns:
            if str(col).startswith('Unnamed'):
                # 检查该列是否全为空
                if not df[col].isna().all():
                    original_columns.append(col)  # 保留有数据的Unnamed列
                    print(f"保留有数据的Unnamed列: {col}")
                else:
                    print(f"跳过空的Unnamed列: {col}")
                # 跳过空的Unnamed列
            else:
                original_columns.append(col)  # 保留所有非Unnamed列
        save_columns = original_columns + ['prompt7', 'ds_thinking7', 'ds_response7']
        # 去重并保持原有顺序
        save_columns = list(dict.fromkeys(save_columns))
        # 确保所有需要保存的列都存在
        save_columns = [col for col in save_columns if col in new_df.columns]
        df_to_save = new_df[save_columns]
        save_file(df_to_save, output_file)
        print(f"增量更新完成！只保存原有列和新增的三个字段，共 {len(save_columns)} 列，结果已保存到 {output_file}")
    else:
        # 完整处理模式：保存所有列
        save_file(new_df, output_file)
        print(f"完整处理完成！结果已保存到 {output_file}")
    
    # 统计结果
    print(f"\n统计结果:")
    print(f"原始总记录数: {len(df)}")
    print(f"有效记录数: {len(df_valid)}")
    print(f"跳过记录数: {len(invalid_rows)}")
    print(f"处理记录数: {len(new_df)}")
    
    if only_new_fields:
        print(f"增量更新模式：只处理了新增的三个字段（prompt7, ds_thinking7, ds_response7）")
    else:
        # 完整处理模式：进行详细统计
        correct_count = (new_df['is_correct'] == '√').sum()
        total_count = len(new_df[new_df['is_correct'].isin(['√', '×'])])
        accuracy = correct_count / total_count * 100 if total_count > 0 else 0
        
        # 人工校正统计
        manual_review_count = (new_df['manual_review_needed'] == '是').sum()
        manual_review_rate = manual_review_count / len(new_df) * 100 if len(new_df) > 0 else 0
        
        print(f"成功处理: {total_count}")
        print(f"正确匹配: {correct_count}")
        print(f"准确率: {accuracy:.2f}%")
        print(f"需要人工校正: {manual_review_count}/{len(new_df)} ({manual_review_rate:.2f}%)")
        
        # 如果有需要人工校正的记录，生成单独的文件
        if manual_review_count > 0:
            manual_review_df = new_df[new_df['manual_review_needed'] == '是'].copy()
            manual_review_file = os.path.splitext(output_file)[0] + "_manual_review.csv"
            save_file(manual_review_df, manual_review_file)
            print(f"需要人工校正的 {manual_review_count} 条记录已保存到: {manual_review_file}")

def validate_correct_result_column(input_file: str, bailian_api_key: str, max_workers: int = 5):
    """
    验证文件中correct_result列的CWE提取准确性（补丁函数）
    
    Args:
        input_file: 输入文件路径（包含correct_result列的文件）
        bailian_api_key: 百炼API密钥
        max_workers: 最大线程数
    """
    print(f"开始验证 correct_result 列: {input_file}")
    
    # 生成输出文件名
    base_name = os.path.splitext(input_file)[0]
    output_file = f"{base_name}_validated.csv"
    failed_file = f"{base_name}_manual_fix_needed.csv"
    
    # 读取文件
    df = read_file(input_file)
    
    # 检查必需的列
    required_columns = ['correct_result', 'cwe_list']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"缺少必需的列: {missing_columns}")
    
    print(f"文件读取成功，共 {len(df)} 行数据")
    
    # 初始化分析器用于CWE提取
    analyzer = DeepSeekAnalyzer("", bailian_api_key, use_model_extraction=True)
    
    def process_row(idx):
        """处理单行数据"""
        row = df.loc[idx].copy()
        try:
            print(f"验证第 {idx + 1}/{len(df)} 条...")
            
            correct_result = row['correct_result']
            original_cwe = row['cwe_list']
            
            if pd.isna(correct_result) or correct_result == '':
                extracted_cwe = []
                validation_result = '×'
                failure_reason = 'correct_result为空'
            else:
                # 使用模型提取CWE
                extracted_cwe = analyzer.extract_cwe_from_output(correct_result)
                
                # 检查是否能覆盖真实标签
                validation_result = analyzer.check_cwe_correctness(original_cwe, extracted_cwe)
                
                if validation_result == '√':
                    failure_reason = ''
                else:
                    failure_reason = f"CWE提取不匹配：期望{original_cwe}，实际提取{extracted_cwe}"
            
            time.sleep(0.5)  # 添加延迟避免API限流
            return idx, extracted_cwe, validation_result, failure_reason
            
        except Exception as e:
            print(f"验证第 {idx + 1} 条时出错: {e}")
            return idx, [], '×', f'处理错误: {e}'
    
    # 多线程处理
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_row, idx) for idx in df.index]
        
        for future in concurrent.futures.as_completed(futures):
            idx, extracted_cwe, validation_result, failure_reason = future.result()
            results[idx] = (extracted_cwe, validation_result, failure_reason)
    
    # 更新DataFrame
    extracted_cwe_list = []
    validation_result_list = []
    failure_reason_list = []
    
    for idx in df.index:
        if idx in results:
            extracted_cwe, validation_result, failure_reason = results[idx]
            extracted_cwe_list.append(format_cwe_result(extracted_cwe))
            validation_result_list.append(validation_result)
            failure_reason_list.append(failure_reason)
        else:
            extracted_cwe_list.append('处理失败')
            validation_result_list.append('×')
            failure_reason_list.append('处理失败')
    
    # 添加验证结果列
    df['validation_result'] = validation_result_list
    df['failure_reason'] = failure_reason_list
    
    # 统计结果
    total_rows = len(df)
    success_count = (df['validation_result'] == '√').sum()
    fail_count = (df['validation_result'] == '×').sum()
    
    print(f"\n验证结果统计:")
    print(f"总条数: {total_rows}")
    print(f"验证成功: {success_count} ({success_count/total_rows*100:.2f}%)")
    print(f"验证失败: {fail_count} ({fail_count/total_rows*100:.2f}%)")
    
    # 保存所有验证结果
    save_file(df, output_file)
    print(f"完整验证结果已保存到: {output_file}")
    
    # 筛选并保存失败的记录
    if fail_count > 0:
        failed_df = df[df['validation_result'] == '×'].copy()
        save_file(failed_df, failed_file)
        print(f"需要人工修正的 {fail_count} 条记录已保存到: {failed_file}")
    else:
        print("所有记录验证通过，无需人工修正！")
    
    return output_file, failed_file

if __name__ == "__main__":
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("错误: 找不到 config.json 文件，请确保配置文件存在")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: config.json 文件格式不正确: {e}")
        exit(1)
    except Exception as e:
        print(f"错误: 读取配置文件时出错: {e}")
        exit(1)
    
    # 检查必需的配置项
    required_configs = ["INPUT_FILE", "DEEPSEEK_API_KEY"]
    missing_configs = [key for key in required_configs if key not in config]
    if missing_configs:
        print(f"错误: 配置文件中缺少必需的配置项: {missing_configs}")
        exit(1)
    
    # 配置参数
    INPUT_FILE = config["INPUT_FILE"] # 输入文件路径（支持 .csv, .xlsx, .xls）
    # 输出文件名根据输出路径文件名命令，加上 result 后缀
    OUTPUT_FILE = os.path.splitext(os.path.basename(INPUT_FILE))[0] + "_result.csv"
    API_KEY = config["DEEPSEEK_API_KEY"]  # 从配置文件获取API密钥
    
    # 处理百炼API配置异常
    BAILIAN_API_KEY = config.get("BAILIAN_API_KEY", "")
    if not BAILIAN_API_KEY or BAILIAN_API_KEY == "your_bailian_api_key":
        print("警告: 百炼API配置异常，将使用DeepSeek API替代")
        BAILIAN_API_KEY = "your_bailian_api_key"  # 设置为默认值，在DeepSeekAnalyzer中会处理
    
    MAX_WORKERS = config.get("MAX_WORKERS", 5)  # 最大线程数，默认为5
    SHEET_NAME = None  # Excel工作表名称，None表示使用第一个工作表
    USE_MODEL_EXTRACTION = True
    ONLY_NEW_FIELDS = config.get("ONLY_NEW_FIELDS", False)  # 是否只处理新增的三个字段，默认为False
    
    print(f"配置信息:")
    print(f"输入文件: {INPUT_FILE}")
    print(f"输出文件: {OUTPUT_FILE}")
    print(f"最大线程数: {MAX_WORKERS}")
    if ONLY_NEW_FIELDS:
        print(f"处理模式: 增量更新 - 只处理新增字段 (prompt7, ds_thinking7, ds_response7)")
        print(f"注意: 将跳过其他所有字段的处理，适用于已处理过的文件")
    else:
        print(f"处理模式: 完整处理 - 处理所有字段")
    print("-" * 60)
    
    start_time = time.time()
    process_file(INPUT_FILE, OUTPUT_FILE, API_KEY, BAILIAN_API_KEY, sheet_name=SHEET_NAME, max_workers=MAX_WORKERS, use_model_extraction=USE_MODEL_EXTRACTION, only_new_fields=ONLY_NEW_FIELDS)
    # 后处理：检查并重新处理缺失的行
    post_process_missing_rows(OUTPUT_FILE, API_KEY, BAILIAN_API_KEY, max_workers=MAX_WORKERS, use_model_extraction=USE_MODEL_EXTRACTION, only_new_fields=ONLY_NEW_FIELDS)
    end_time = time.time()
    print(f"处理完成！总耗时: {(end_time - start_time) / 60:.2f}分钟")
