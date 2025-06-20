import pandas as pd
from openai import OpenAI
import json
import time
import ast
import re
import os
import json
from typing import Dict, Any, Tuple, Optional
import concurrent.futures

class DeepSeekAnalyzer:
    def __init__(self, api_key: str):
        """
        初始化DeepSeek分析器
        
        Args:
            api_key: DeepSeek API密钥
        """
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
    
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
可能存在漏洞代码的区间：{changed_statements}
{cve_section}
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
    
    def extract_cwe_from_output(self, output: str) -> list:
        """
        从输出结果中提取CWE编号
        
        Args:
            output: 分析输出结果
            
        Returns:
            list: CWE编号列表
        """
        if not output:
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
            return list(set(re.findall(cwe_pattern, output)))
        
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

    def generate_correct_output_with_retry(self, func_body: str, original_cwe: str, cve_info: str, changed_statements: str) -> str:
        """
        生成correct_output并进行验证，如果需要则重试一次
        
        Args:
            func_body: 函数体代码
            original_cwe: 原始CWE信息
            cve_info: CVE信息
            changed_statements: 可能存在漏洞代码的区间
            
        Returns:
            str: 最终的correct_output内容
        """
        cwe_info = format_cwe_info(original_cwe)
        if not cwe_info:
            return ''
        
        # 检查是否为"NVD-CWE-noinfo"，如果是则不需要验证
        is_no_info = "NVD-CWE-noinfo" in original_cwe or "noinfo" in original_cwe.lower()
        
        # 第一次生成
        _, correct_content = self.analyze_with_correct_cwe(func_body, cwe_info, cve_info, changed_statements)
        
        # 如果是noinfo或者验证通过，直接返回
        if is_no_info:
            print("CWE为noinfo类型，无需验证，直接使用生成结果")
            return correct_content
        
        # 验证生成的内容是否包含正确的CWE
        extracted_cwe = self.extract_cwe_from_output(correct_content)
        is_correct = self.check_cwe_correctness(original_cwe, extracted_cwe)
        
        if is_correct == '√':
            print("生成的correct_output验证通过")
            return correct_content
        else:
            print("生成的correct_output验证失败，重试一次...")
            # 重试一次
            _, retry_content = self.analyze_with_correct_cwe(func_body, cwe_info, cve_info, changed_statements)
            print("重试完成")
            return retry_content

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

def process_file(input_file: str, output_file: str, api_key: str, batch_size: int = 5, 
                sheet_name: str = None, save_chunks: bool = True, max_workers: int=5, **file_kwargs):
    """
    处理文件（支持CSV和XLSX）
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        api_key: DeepSeek API密钥
        batch_size: 批处理大小，每处理这么多条记录就保存一次分片
        sheet_name: Excel工作表名称（仅对xlsx文件有效）
        save_chunks: 是否保存分片文件
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
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer(api_key)
    
    # 添加新列（如果不存在）
    if 'ds_think' not in df.columns:
        df['ds_think'] = ''
    if 'ds_output' not in df.columns:
        df['ds_output'] = ''
    if 'ds_result' not in df.columns:  # 新增列
        df['ds_result'] = ''
    if 'is_correct' not in df.columns:
        df['is_correct'] = ''
    if 'correct_output' not in df.columns:
        df['correct_output'] = ''
    if 'ds_think_reduced' not in df.columns:  # 新增删减后的思维链列
        df['ds_think_reduced'] = ''
    
    print(f"开始处理 {len(df)} 条记录...")
    
    def get_ds_result(idx, row):
        # 先基于 row 复制一个新行出来
        new_row = row.copy()
        try:
            print(f"处理第 {idx + 1}/{len(df)} 条记录...")
            
            func_body = new_row['func_body']
            if pd.isna(func_body) or func_body == '':
                new_row['ds_think'] = '函数体为空'
                new_row['ds_output'] = ''
                new_row['ds_result'] = '无漏洞'  # 新增
                new_row['is_correct'] = '×'
                new_row['correct_output'] = ''
                new_row['ds_think_reduced'] = ''  # 新增
                return new_row
            
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
                print(f"第 {idx + 1} 条处理完成 - 判断正确，直接复制输出")
            else:
                # 如果不正确，使用正确CWE重新调用API
                cwe_info = format_cwe_info(original_cwe)
                if cwe_info:
                    print(f"第 {idx + 1} 条判断错误，使用正确CWE重新分析: {cwe_info}")
                    changed_statements = row.get('changed_statements', '')  # 获取changed_statements字段，默认为空
                    cve_list = row.get('cve_list', '')  # 获取cve_list字段，默认为空
                    correct_content = analyzer.generate_correct_output_with_retry(func_body, original_cwe, cve_list, changed_statements)
                    new_row['correct_output'] = correct_content
                    print(f"第 {idx + 1} 条二次分析完成")
                else:
                    new_row['correct_output'] = ''
                    print(f"第 {idx + 1} 条无有效CWE信息")
            
            # 对ds_think进行删减处理
            if reasoning_content:
                print(f"第 {idx + 1} 条正在删减思维链内容，原长度: {len(reasoning_content)} 字符")
                reduced_thinking = analyzer.reduce_thinking_content(reasoning_content)
                new_row['ds_think_reduced'] = reduced_thinking
                print(f"第 {idx + 1} 条思维链删减完成，新长度: {len(reduced_thinking)} 字符")
            else:
                new_row['ds_think_reduced'] = ''
            
            print(f"第 {idx + 1} 条原始CWE: {original_cwe}")
            print(f"第 {idx + 1} 条提取CWE: {extracted_cwe}")
            print(f"第 {idx + 1} 条DS结果: {df.at[idx, 'ds_result']}")  # 新增
            print(f"第 {idx + 1} 条正确性: {is_correct}")
            print(f"第 {idx + 1} 条思维链长度: {len(reasoning_content)} 字符")
            print(f"第 {idx + 1} 条正式输出: {content[:100]}..." if len(content) > 100 else f"正式输出: {content}")
            print("-" * 50)
            
            # 添加延迟避免API限流
            time.sleep(1)
            return new_row
            
        except Exception as e:
            print(f"处理第 {idx + 1} 条记录时出错: {e}")
            new_row['ds_think'] = f'处理错误: {e}'
            new_row['ds_output'] = ''
            new_row['ds_result'] = '处理错误'  # 新增
            new_row['is_correct'] = '×'
            new_row['correct_output'] = ''
            new_row['ds_think_reduced'] = ''  # 新增
            return new_row
    
    new_df = pd.DataFrame(columns=df.columns)
    # 多线程处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        futures = [executor.submit(get_ds_result, idx, row) for idx, row in df.iterrows()]
        # 收集结果
        for future in concurrent.futures.as_completed(futures):
            new_row = future.result()
            new_df = pd.concat([new_df, pd.DataFrame([new_row])], ignore_index=True)
    
    # print(new_df)
    
    # 最终保存完整文件
    save_file(new_df, output_file)
    print(f"处理完成！结果已保存到 {output_file}")
    
    # 统计结果
    correct_count = (new_df['is_correct'] == '√').sum()
    total_count = len(new_df[new_df['is_correct'].isin(['√', '×'])])
    accuracy = correct_count / total_count * 100 if total_count > 0 else 0
    
    print(f"\n统计结果:")
    print(f"总记录数: {len(new_df)}")
    print(f"成功处理: {total_count}")
    print(f"正确匹配: {correct_count}")
    print(f"准确率: {accuracy:.2f}%")

if __name__ == "__main__":
    with open("config.json", "r") as f:
        config = json.load(f)
    # 配置参数
    INPUT_FILE = config["INPUT_FILE"] # 输入文件路径（支持 .csv, .xlsx, .xls）
    OUTPUT_FILE = "output_with_analysis.csv"  # 输出文件路径
    API_KEY = config["DEEPSEEK_API_KEY"]  # 从配置文件获取API密钥
    MAX_WORKERS = config["MAX_WORKERS"] if "MAX_WORKERS" in config else 5  # 最大线程数，默认为5
    SHEET_NAME = None  # Excel工作表名称，None表示使用第一个工作表

    # 由于并行速度够快，分片处理逻辑已删除，下面两行可忽略    
    BATCH_SIZE = 5  # 每处理5条记录保存一次分片
    SAVE_CHUNKS = True  # 是否保存分片文件
    
    start_time = time.time()
    process_file(INPUT_FILE, OUTPUT_FILE, API_KEY, batch_size=BATCH_SIZE, 
                 sheet_name=SHEET_NAME, save_chunks=SAVE_CHUNKS, max_workers=MAX_WORKERS)
    end_time = time.time()
    print(f"处理完成！总耗时: {(end_time - start_time) / 60:.2f}分钟")