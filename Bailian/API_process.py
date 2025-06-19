import pandas as pd
from openai import OpenAI
import json
import time
import ast
import re
import os
import json
from typing import Dict, Any, Tuple, Optional

class DeepSeekAnalyzer:
    def __init__(self, api_key: str):
        """
        初始化DeepSeek分析器
        
        Args:
            api_key: DeepSeek API密钥
        """
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
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
                model="deepseek-r1-0528",
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
    
    def analyze_with_correct_cwe(self, func_body: str, cwe_info: str) -> Tuple[str, str]:
        """
        使用正确的CWE信息重新分析函数漏洞
        
        Args:
            func_body: 函数体代码
            cwe_info: 正确的CWE信息
            
        Returns:
            tuple: (思维链reasoning_content, 正式输出结果content)
        """
        prompt = f"""
{func_body}
上述代码存在{cwe_info}漏洞，请仔细分析这段程序，找出存在漏洞的代码并分析其潜在的风险（注意不要生成修复建议等无关内容）。
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
                model="deepseek-r1-0528",
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
        
        # 检查是否有交集
        return '√' if original_cwe_numbers.intersection(extracted_cwe_numbers) else '×'

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
        # 默认参数，可以被kwargs覆盖
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

def create_chunk_filename(base_filename: str, chunk_num: int, total_chunks: int = None) -> str:
    """
    创建分片文件名
    
    Args:
        base_filename: 基础文件名，如 "output.xlsx"
        chunk_num: 分片编号（从1开始）
        total_chunks: 总分片数（可选）
        
    Returns:
        str: 分片文件名，如 "output_chunk_1.xlsx"
    """
    name, ext = os.path.splitext(base_filename)
    if total_chunks:
        return f"{name}_chunk_{chunk_num:03d}_of_{total_chunks:03d}{ext}"
    else:
        return f"{name}_chunk_{chunk_num:03d}{ext}"

def process_file(input_file: str, output_file: str, api_key: str, batch_size: int = 5, 
                sheet_name: str = None, save_chunks: bool = True, **file_kwargs):
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
    required_columns = ['func_body', 'cwe']
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
    
    print(f"开始处理 {len(df)} 条记录...")
    
    # 计算总分片数
    total_chunks = (len(df) + batch_size - 1) // batch_size if save_chunks else None
    chunk_num = 0
    
    for idx, row in df.iterrows():
        try:
            print(f"处理第 {idx + 1}/{len(df)} 条记录...")
            
            func_body = row['func_body']
            if pd.isna(func_body) or func_body == '':
                df.at[idx, 'ds_think'] = '函数体为空'
                df.at[idx, 'ds_output'] = ''
                df.at[idx, 'ds_result'] = '无漏洞'  # 新增
                df.at[idx, 'is_correct'] = '×'
                df.at[idx, 'correct_output'] = ''
                continue
            
            # 调用API分析
            reasoning_content, content = analyzer.analyze_function(func_body)
            
            # 存储结果
            df.at[idx, 'ds_think'] = reasoning_content
            df.at[idx, 'ds_output'] = content
            
            # 提取CWE并检查正确性
            extracted_cwe = analyzer.extract_cwe_from_output(content)
            df.at[idx, 'ds_result'] = format_cwe_result(extracted_cwe)  # 新增
            
            original_cwe = row['cwe']
            is_correct = analyzer.check_cwe_correctness(original_cwe, extracted_cwe)
            df.at[idx, 'is_correct'] = is_correct
            
            # 根据正确性处理correct_output
            if is_correct == '√':
                # 如果正确，直接复制ds_output到correct_output
                df.at[idx, 'correct_output'] = content
                print(f"第 {idx + 1} 条处理完成 - 判断正确，直接复制输出")
            else:
                # 如果不正确，使用正确CWE重新调用API
                cwe_info = format_cwe_info(original_cwe)
                if cwe_info:
                    print(f"第 {idx + 1} 条判断错误，使用正确CWE重新分析: {cwe_info}")
                    _, correct_content = analyzer.analyze_with_correct_cwe(func_body, cwe_info)
                    df.at[idx, 'correct_output'] = correct_content
                    print(f"二次分析完成")
                else:
                    df.at[idx, 'correct_output'] = ''
                    print(f"第 {idx + 1} 条无有效CWE信息")
            
            print(f"原始CWE: {original_cwe}")
            print(f"提取CWE: {extracted_cwe}")
            print(f"DS结果: {df.at[idx, 'ds_result']}")  # 新增
            print(f"正确性: {is_correct}")
            print(f"思维链长度: {len(reasoning_content)} 字符")
            print(f"正式输出: {content[:100]}..." if len(content) > 100 else f"正式输出: {content}")
            print("-" * 50)
            
            # 每处理batch_size条记录保存一次分片
            if (idx + 1) % batch_size == 0:
                chunk_num += 1
                
                # 保存分片文件
                if save_chunks:
                    chunk_filename = create_chunk_filename(output_file, chunk_num, total_chunks)
                    # 保存当前分片的数据（从当前位置往前batch_size条）
                    start_idx = max(0, idx + 1 - batch_size)
                    chunk_df = df.iloc[start_idx:idx + 1].copy()
                    save_file(chunk_df, chunk_filename)
                    print(f"已保存分片 {chunk_num}: {chunk_filename} (记录 {start_idx + 1}-{idx + 1})")
                
                # 保存完整文件
                save_file(df, output_file)
                print(f"已保存完整进度到 {output_file}")
            
            # 添加延迟避免API限流
            time.sleep(1)
            
        except Exception as e:
            print(f"处理第 {idx + 1} 条记录时出错: {e}")
            df.at[idx, 'ds_think'] = f'处理错误: {e}'
            df.at[idx, 'ds_output'] = ''
            df.at[idx, 'ds_result'] = '处理错误'  # 新增
            df.at[idx, 'is_correct'] = '×'
            df.at[idx, 'correct_output'] = ''
    
    # 保存最后一个分片（如果有剩余记录）
    remaining_records = len(df) % batch_size
    if save_chunks and remaining_records > 0:
        chunk_num += 1
        chunk_filename = create_chunk_filename(output_file, chunk_num, total_chunks)
        start_idx = len(df) - remaining_records
        chunk_df = df.iloc[start_idx:].copy()
        save_file(chunk_df, chunk_filename)
        print(f"已保存最后分片 {chunk_num}: {chunk_filename} (记录 {start_idx + 1}-{len(df)})")
    
    # 最终保存完整文件
    save_file(df, output_file)
    print(f"处理完成！结果已保存到 {output_file}")
    
    # 统计结果
    correct_count = (df['is_correct'] == '√').sum()
    total_count = len(df[df['is_correct'].isin(['√', '×'])])
    accuracy = correct_count / total_count * 100 if total_count > 0 else 0
    
    print(f"\n统计结果:")
    print(f"总记录数: {len(df)}")
    print(f"成功处理: {total_count}")
    print(f"正确匹配: {correct_count}")
    print(f"准确率: {accuracy:.2f}%")

def resume_processing(input_file: str, output_file: str, api_key: str, batch_size: int = 5,
                     sheet_name: str = None, save_chunks: bool = True, **file_kwargs):
    """
    恢复处理（从已有的输出文件继续处理未完成的部分）
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径（如果存在会继续处理）
        api_key: DeepSeek API密钥
        batch_size: 批处理大小
        sheet_name: Excel工作表名称（仅对xlsx文件有效）
        save_chunks: 是否保存分片文件
        **file_kwargs: 传递给文件读取函数的额外参数
    """
    try:
        # 尝试读取已有的输出文件
        df = read_file(output_file)
        print(f"找到已有输出文件，从断点继续处理...")
    except FileNotFoundError:
        # 如果输出文件不存在，从头开始
        read_kwargs = file_kwargs.copy()
        if sheet_name and get_file_extension(input_file) in ['.xlsx', '.xls']:
            read_kwargs['sheet_name'] = sheet_name
        
        df = read_file(input_file, **read_kwargs)
        df['ds_think'] = ''
        df['ds_output'] = ''
        df['ds_result'] = ''  # 新增
        df['is_correct'] = ''
        df['correct_output'] = ''
        print(f"输出文件不存在，从头开始处理...")
    
    # 检查必需的列
    required_columns = ['func_body', 'cwe']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"缺少必需的列: {missing_columns}")
    
    # 确保所有必需列存在
    if 'correct_output' not in df.columns:
        df['correct_output'] = ''
    if 'ds_result' not in df.columns:  # 新增
        df['ds_result'] = ''
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer(api_key)
    
    # 找到未处理的记录
    unprocessed_mask = (
        (df['ds_think'] == '') | (df['ds_think'].isna()) | 
        (df['correct_output'] == '') | (df['correct_output'].isna()) |
        (df['ds_result'] == '') | (df['ds_result'].isna())  # 新增条件
    )
    unprocessed_indices = df[unprocessed_mask].index.tolist()
    
    if not unprocessed_indices:
        print("所有记录都已处理完成！")
        return
    
    print(f"发现 {len(unprocessed_indices)} 条未完全处理记录，继续处理...")
    
    # 计算分片信息
    total_chunks = (len(unprocessed_indices) + batch_size - 1) // batch_size if save_chunks else None
    chunk_num = 0
    
    for i, idx in enumerate(unprocessed_indices):
        try:
            row = df.loc[idx]
            print(f"处理第 {i + 1}/{len(unprocessed_indices)} 条未处理记录 (总第 {idx + 1} 条)...")
            
            func_body = row['func_body']
            if pd.isna(func_body) or func_body == '':
                df.at[idx, 'ds_think'] = '函数体为空'
                df.at[idx, 'ds_output'] = ''
                df.at[idx, 'ds_result'] = '无漏洞'  # 新增
                df.at[idx, 'is_correct'] = '×'
                df.at[idx, 'correct_output'] = ''
                continue
            
            # 如果ds_think为空，进行初次分析
            if pd.isna(df.at[idx, 'ds_think']) or df.at[idx, 'ds_think'] == '':
                reasoning_content, content = analyzer.analyze_function(func_body)
                df.at[idx, 'ds_think'] = reasoning_content
                df.at[idx, 'ds_output'] = content
                
                # 提取CWE并检查正确性
                extracted_cwe = analyzer.extract_cwe_from_output(content)
                df.at[idx, 'ds_result'] = format_cwe_result(extracted_cwe)  # 新增
                original_cwe = row['cwe']
                is_correct = analyzer.check_cwe_correctness(original_cwe, extracted_cwe)
                df.at[idx, 'is_correct'] = is_correct
            else:
                # 如果已有初次分析结果，获取正确性判断
                is_correct = df.at[idx, 'is_correct']
                content = df.at[idx, 'ds_output']
                
                # 检查ds_result是否为空，如果为空则重新提取
                if pd.isna(df.at[idx, 'ds_result']) or df.at[idx, 'ds_result'] == '':
                    extracted_cwe = analyzer.extract_cwe_from_output(content)
                    df.at[idx, 'ds_result'] = format_cwe_result(extracted_cwe)
            
            # 如果correct_output为空，根据正确性处理
            if pd.isna(df.at[idx, 'correct_output']) or df.at[idx, 'correct_output'] == '':
                if is_correct == '√':
                    # 如果正确，直接复制ds_output到correct_output
                    df.at[idx, 'correct_output'] = content
                    print(f"判断正确，直接复制输出")
                else:
                    # 如果不正确，使用正确CWE重新调用API
                    original_cwe = row['cwe']
                    cwe_info = format_cwe_info(original_cwe)
                    if cwe_info:
                        print(f"判断错误，使用正确CWE重新分析: {cwe_info}")
                        _, correct_content = analyzer.analyze_with_correct_cwe(func_body, cwe_info)
                        df.at[idx, 'correct_output'] = correct_content
                        print(f"二次分析完成")
                    else:
                        df.at[idx, 'correct_output'] = ''
                        print(f"无有效CWE信息")
            
            print(f"处理完成 - 正确性: {is_correct}, DS结果: {df.at[idx, 'ds_result']}")
            
            # 每处理batch_size条记录保存一次分片
            if (i + 1) % batch_size == 0:
                chunk_num += 1
                
                if save_chunks:
                    chunk_filename = create_chunk_filename(output_file, chunk_num, total_chunks)
                    # 获取当前批次处理的记录
                    current_batch_indices = unprocessed_indices[max(0, i + 1 - batch_size):i + 1]
                    chunk_df = df.loc[current_batch_indices].copy()
                    save_file(chunk_df, chunk_filename)
                    print(f"已保存处理分片 {chunk_num}: {chunk_filename}")
                
                save_file(df, output_file)
                print(f"已保存进度到 {output_file}")
            
            # 添加延迟避免API限流
            time.sleep(1)
            
        except Exception as e:
            print(f"处理第 {idx + 1} 条记录时出错: {e}")
            df.at[idx, 'ds_think'] = f'处理错误: {e}'
            df.at[idx, 'ds_output'] = ''
            df.at[idx, 'ds_result'] = '处理错误'  # 新增
            df.at[idx, 'is_correct'] = '×'
            df.at[idx, 'correct_output'] = ''
    
    # 保存最后一个分片（如果有剩余记录）
    remaining_records = len(unprocessed_indices) % batch_size
    if save_chunks and remaining_records > 0:
        chunk_num += 1
        chunk_filename = create_chunk_filename(output_file, chunk_num, total_chunks)
        start_idx = len(unprocessed_indices) - remaining_records
        remaining_indices = unprocessed_indices[start_idx:]
        chunk_df = df.loc[remaining_indices].copy()
        save_file(chunk_df, chunk_filename)
        print(f"已保存最后处理分片 {chunk_num}: {chunk_filename}")
    
    # 最终保存
    save_file(df, output_file)
    print(f"处理完成！结果已保存到 {output_file}")

if __name__ == "__main__":
    # 配置参数
    INPUT_FILE = "sample_3.csv"  # 输入文件路径（支持 .csv, .xlsx, .xls）
    OUTPUT_FILE = "output_with_analysis.csv"  # 输出文件路径
    # API_KEY = "sk-044fb6603b7b4185b4ea6c876df52833"  # 替换为你的DeepSeek API密钥
    with open("config.json", "r") as f:
        config = json.load(f)
    API_KEY = config["BAILIAN_API_KEY"]  # 从配置文件获取API密钥
    SHEET_NAME = None  # Excel工作表名称，None表示使用第一个工作表
    BATCH_SIZE = 5  # 每处理5条记录保存一次分片
    SAVE_CHUNKS = True  # 是否保存分片文件
    
    # 方式1: 从头开始处理
    # process_file(INPUT_FILE, OUTPUT_FILE, API_KEY, batch_size=BATCH_SIZE, 
    #              sheet_name=SHEET_NAME, save_chunks=SAVE_CHUNKS)
    
    # 方式2: 恢复处理（推荐）- 可以从断点继续
    resume_processing(INPUT_FILE, OUTPUT_FILE, API_KEY, batch_size=BATCH_SIZE, 
                     sheet_name=SHEET_NAME, save_chunks=SAVE_CHUNKS)