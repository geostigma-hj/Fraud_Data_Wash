#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新处理已有文件的 ds_result 和 is_correct 列

这个脚本用于处理已经使用旧版本代码处理过的文件，
重新使用模型提取 CWE 编号并更新 ds_result 和 is_correct 列。
"""

import pandas as pd
import json
import time
import os
from typing import Optional
import concurrent.futures

# 导入API_process.py中的现有功能
from API_process import (
    DeepSeekAnalyzer,
    read_file,
    save_file,
    format_cwe_result
)

class DSResultUpdater(DeepSeekAnalyzer):
    """
    DS结果更新器，继承DeepSeekAnalyzer以重用现有功能
    """
    def __init__(self, bailian_api_key: str):
        """
        初始化ds_result更新器
        
        Args:
            bailian_api_key: 百炼API密钥，用于调用DeepSeek V3
        """
        # 只需要百炼API功能，所以DeepSeek API密钥传空字符串
        super().__init__(api_key="", bailian_api_key=bailian_api_key, use_model_extraction=True)

# 比较两个 ds_output 是否相同
def compare_ds_output(ds_output1: str, ds_output2: str) -> bool:
    # 首先进行分割
    ds_output1_list = ds_output1.split(", ")
    ds_output2_list = ds_output2.split(", ")
    # 然后进行比较
    for item1 in ds_output1_list:
        if item1 not in ds_output2_list:
            return False
    return True

def update_ds_result_file(input_file: str, output_file: str, bailian_api_key: str, max_workers: int = 5):
    """
    更新已有文件的ds_result和is_correct列
    
    Args:
        input_file: 输入文件路径（已经处理过的文件）
        output_file: 输出文件路径
        bailian_api_key: 百炼API密钥
        max_workers: 最大线程数
    """
    print(f"正在读取文件: {input_file}")
    df = read_file(input_file)
    
    # 检查必需的列
    required_columns = ['ds_output', 'cwe_list']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"缺少必需的列: {missing_columns}")
    
    print(f"文件读取成功，共 {len(df)} 行数据")
    print(f"列名: {list(df.columns)}")
    
    # 保存原始的ds_result和is_correct列（如果存在）
    original_ds_result = df['ds_result'].copy() if 'ds_result' in df.columns else pd.Series([''] * len(df))
    original_is_correct = df['is_correct'].copy() if 'is_correct' in df.columns else pd.Series([''] * len(df))
    
    # 初始化更新器
    updater = DSResultUpdater(bailian_api_key)
    
    def process_row(idx):
        """处理单行数据"""
        row = df.loc[idx].copy()
        try:
            print(f"处理第 {idx + 1}/{len(df)} 条...")
            
            ds_output = row['ds_output']
            if pd.isna(ds_output) or ds_output == '':
                new_ds_result = '无漏洞'
                new_is_correct = '×'
                print(f"第 {idx + 1} 条: ds_output为空，设置为无漏洞")
            else:
                # 使用模型提取CWE
                extracted_cwe = updater.extract_cwe_from_output(ds_output)
                new_ds_result = format_cwe_result(extracted_cwe)
                
                # 检查正确性
                original_cwe = row['cwe_list']
                new_is_correct = updater.check_cwe_correctness(original_cwe, extracted_cwe)
                
                print(f"第 {idx + 1} 条: 提取CWE: {extracted_cwe}, 结果: {new_ds_result}, 正确性: {new_is_correct}")
            
            # 添加延迟避免API限流
            time.sleep(1)
            return idx, new_ds_result, new_is_correct
            
        except Exception as e:
            print(f"处理第 {idx + 1} 条时出错: {e}")
            return idx, '处理错误', '×'
    
    # 多线程处理
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_row, idx) for idx in df.index]
        
        for future in concurrent.futures.as_completed(futures):
            idx, new_ds_result, new_is_correct = future.result()
            results[idx] = (new_ds_result, new_is_correct)
    
    # 更新DataFrame
    new_ds_result_list = []
    new_is_correct_list = []
    
    for idx in df.index:
        if idx in results:
            new_ds_result, new_is_correct = results[idx]
            new_ds_result_list.append(new_ds_result)
            new_is_correct_list.append(new_is_correct)
        else:
            new_ds_result_list.append('处理失败')
            new_is_correct_list.append('×')
    
    # 添加新的列
    df['ds_result_new'] = new_ds_result_list
    df['is_correct_new'] = new_is_correct_list
    
    # 如果原始列存在，保留作为对比
    if 'ds_result' not in df.columns:
        df['ds_result_old'] = ''
    else:
        df['ds_result_old'] = original_ds_result
        
    if 'is_correct' not in df.columns:
        df['is_correct_old'] = ''
    else:
        df['is_correct_old'] = original_is_correct
    
    # 更新原始列
    df['ds_result'] = df['ds_result_new']
    df['is_correct'] = df['is_correct_new']
    
    # 统计和对比结果
    print("\n" + "="*60)
    print("处理结果统计")
    print("="*60)
    
    # 基本统计
    total_rows = len(df)
    print(f"总条数: {total_rows}")
    
    # ds_result变化统计
    # 如果只有顺序变化，则不统计为变化，只统计内容变化
    ds_result_changed = 0
    for i in df.index:
        old_val = str(df.at[i, 'ds_result_old']).strip()
        new_val = str(df.at[i, 'ds_result_new']).strip()
        if not compare_ds_output(old_val, new_val):
            ds_result_changed += 1
    
    print(f"ds_result发生变化的行数: {ds_result_changed} ({ds_result_changed/total_rows*100:.2f}%)")
    
    # is_correct变化统计
    is_correct_changed = 0
    for i in df.index:
        old_val = str(df.at[i, 'is_correct_old']).strip()
        new_val = str(df.at[i, 'is_correct_new']).strip()
        if old_val != new_val:
            is_correct_changed += 1
    
    print(f"is_correct发生变化的行数: {is_correct_changed} ({is_correct_changed/total_rows*100:.2f}%)")
    
    # 准确率统计
    new_correct_count = (df['is_correct_new'] == '√').sum()
    old_correct_count = (df['is_correct_old'] == '√').sum() if 'is_correct_old' in df.columns else 0
    
    new_accuracy = new_correct_count / total_rows * 100
    old_accuracy = old_correct_count / total_rows * 100 if total_rows > 0 else 0
    
    print(f"\n准确率对比:")
    print(f"原始准确率: {old_correct_count}/{total_rows} ({old_accuracy:.2f}%)")
    print(f"新版准确率: {new_correct_count}/{total_rows} ({new_accuracy:.2f}%)")
    print(f"准确率变化: {new_accuracy - old_accuracy:+.2f}%")
    
    # 详细变化分析
    print(f"\n详细变化分析:")
    
    # ds_result的具体变化
    if ds_result_changed > 0:
        print(f"\nds_result变化示例 (前5个):")
        change_count = 0
        for i in df.index:
            if change_count >= 5:
                break
            old_val = str(df.at[i, 'ds_result_old']).strip()
            new_val = str(df.at[i, 'ds_result_new']).strip()
            if not compare_ds_output(old_val, new_val):
                print(f"  行{i+2}: '{old_val}' -> '{new_val}'")
                change_count += 1
    
    # is_correct的具体变化
    if is_correct_changed > 0:
        print(f"\nis_correct变化统计:")
        wrong_to_right = 0  # × -> √
        right_to_wrong = 0  # √ -> ×
        
        for i in df.index:
            old_val = str(df.at[i, 'is_correct_old']).strip()
            new_val = str(df.at[i, 'is_correct_new']).strip()
            if old_val == '×' and new_val == '√':
                wrong_to_right += 1
            elif old_val == '√' and new_val == '×':
                right_to_wrong += 1
        
        print(f"  错误变正确: {wrong_to_right} 行")
        print(f"  正确变错误: {right_to_wrong} 行")
        print(f"  净提升: {wrong_to_right - right_to_wrong:+d} 行")

    # 删除多余的无关列
    df = df.drop(columns=['ds_result_old', 'is_correct_old', 'ds_result_new', 'is_correct_new'])

    # 保存结果
    save_file(df, output_file)
    print(f"处理完成！结果已保存到 {output_file}")


if __name__ == "__main__":
    # 配置参数
    with open("config.json", "r") as f:
        config = json.load(f)
    
    INPUT_FILE = config["UPDATE_FILE"]
    OUTPUT_FILE = os.path.splitext(INPUT_FILE)[0] + "_updated.csv"
    BAILIAN_API_KEY = config["BAILIAN_API_KEY"]
    MAX_WORKERS = config.get("MAX_WORKERS", 5)
    
    print(f"输入文件: {INPUT_FILE}")
    print(f"输出文件: {OUTPUT_FILE}")
    print(f"最大线程数: {MAX_WORKERS}")
    print("-" * 60)
    
    start_time = time.time()
    update_ds_result_file(INPUT_FILE, OUTPUT_FILE, BAILIAN_API_KEY, MAX_WORKERS)
    end_time = time.time()
    
    print(f"\n处理完成！总耗时: {(end_time - start_time) / 60:.2f}分钟") 