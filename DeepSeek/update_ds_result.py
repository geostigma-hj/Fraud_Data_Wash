#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新处理已有文件的 ds_result 和 is_correct 列，并验证 correct_output 列

这个脚本用于处理已经使用旧版本代码处理过的文件，
重新使用模型提取 CWE 编号并更新 ds_result 和 is_correct 列。
同时支持对 correct_output 列进行二次验证，筛选出需要人工修正的记录。
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

def validate_correct_output_column(df: pd.DataFrame, updater: DSResultUpdater, max_workers: int = 5):
    """
    验证correct_output列的CWE提取准确性
    
    Args:
        df: 包含correct_output列的DataFrame
        updater: DSResultUpdater实例
        max_workers: 最大线程数
        
    Returns:
        tuple: (更新后的DataFrame, 验证失败的记录数)
    """
    print(f"\n开始验证 correct_output 列...")
    
    # 检查是否存在correct_output列
    if 'correct_output' not in df.columns:
        print("未找到correct_output列，跳过验证")
        return df, 0
    
    def validate_row(idx):
        """验证单行数据"""
        row = df.loc[idx].copy()
        try:
            print(f"验证correct_output 第 {idx + 1}/{len(df)} 条...")
            
            correct_output = row['correct_output']
            original_cwe = row['cwe_list']
            
            if pd.isna(correct_output) or correct_output == '':
                extracted_cwe = []
                validation_result = '×'
                failure_reason = 'correct_output为空'
            else:
                # 使用模型提取CWE
                extracted_cwe = updater.extract_cwe_from_output(correct_output)
                
                # 检查是否能覆盖真实标签
                validation_result = updater.check_cwe_correctness(original_cwe, extracted_cwe)
                
                if validation_result == '√':
                    failure_reason = ''
                else:
                    failure_reason = f"CWE提取不匹配：期望{original_cwe}，实际提取{extracted_cwe}"
            
            time.sleep(0.5)  # 添加延迟避免API限流
            return idx, format_cwe_result(extracted_cwe), validation_result, failure_reason
            
        except Exception as e:
            print(f"验证correct_output第 {idx + 1} 条时出错: {e}")
            return idx, '处理错误', '×', f'处理错误: {e}'
    
    # 多线程处理
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(validate_row, idx) for idx in df.index]
        
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
            extracted_cwe_list.append(extracted_cwe)
            validation_result_list.append(validation_result)
            failure_reason_list.append(failure_reason)
        else:
            extracted_cwe_list.append('处理失败')
            validation_result_list.append('×')
            failure_reason_list.append('处理失败')
    
    # 添加验证结果列
    df['correct_output_extracted_cwe'] = extracted_cwe_list
    df['correct_output_validation'] = validation_result_list
    df['correct_output_failure_reason'] = failure_reason_list
    
    # 统计验证结果
    total_rows = len(df)
    success_count = (df['correct_output_validation'] == '√').sum()
    fail_count = (df['correct_output_validation'] == '×').sum()
    
    print(f"\ncorrect_output验证结果统计:")
    print(f"总条数: {total_rows}")
    print(f"验证成功: {success_count} ({success_count/total_rows*100:.2f}%)")
    print(f"验证失败: {fail_count} ({fail_count/total_rows*100:.2f}%)")
    
    return df, fail_count

def update_ds_result_file(input_file: str, output_file: str, bailian_api_key: str, max_workers: int = 5, validate_correct_output: bool = True):
    """
    更新已有文件的ds_result和is_correct列，并可选择验证correct_output列
    
    Args:
        input_file: 输入文件路径（已经处理过的文件）
        output_file: 输出文件路径
        bailian_api_key: 百炼API密钥
        max_workers: 最大线程数
        validate_correct_output: 是否验证correct_output列，默认为True
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

    # correct_output验证
    correct_output_failed_count = 0
    if validate_correct_output:
        df, correct_output_failed_count = validate_correct_output_column(df, updater, max_workers)
        
        # 如果有验证失败的记录，保存到单独文件
        if correct_output_failed_count > 0:
            failed_df = df[df['correct_output_validation'] == '×'].copy()
            failed_output_file = os.path.splitext(output_file)[0] + "_correct_output_failed.csv"
            save_file(failed_df, failed_output_file)
            print(f"correct_output验证失败的 {correct_output_failed_count} 条记录已保存到: {failed_output_file}")

    # 删除多余的无关列
    columns_to_drop = ['ds_result_old', 'is_correct_old', 'ds_result_new', 'is_correct_new']
    # 只删除存在的列
    columns_to_drop = [col for col in columns_to_drop if col in df.columns]
    if columns_to_drop:
        df = df.drop(columns=columns_to_drop)

    # 保存结果
    save_file(df, output_file)
    print(f"处理完成！结果已保存到 {output_file}")


if __name__ == "__main__":
    # 配置参数
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
    required_configs = ["UPDATE_FILE", "BAILIAN_API_KEY"]
    missing_configs = [key for key in required_configs if key not in config]
    if missing_configs:
        print(f"错误: 配置文件中缺少必需的配置项: {missing_configs}")
        exit(1)
    
    INPUT_FILE = config["UPDATE_FILE"]
    OUTPUT_FILE = os.path.splitext(INPUT_FILE)[0] + "_updated.csv"
    BAILIAN_API_KEY = config["BAILIAN_API_KEY"]
    MAX_WORKERS = config.get("MAX_WORKERS", 5)
    VALIDATE_CORRECT_OUTPUT = config.get("VALIDATE_CORRECT_OUTPUT", True)  # 默认启用correct_output验证
    
    print(f"输入文件: {INPUT_FILE}")
    print(f"输出文件: {OUTPUT_FILE}")
    print(f"最大线程数: {MAX_WORKERS}")
    print(f"验证correct_output: {'是' if VALIDATE_CORRECT_OUTPUT else '否'}")
    print("-" * 60)
    
    start_time = time.time()
    update_ds_result_file(INPUT_FILE, OUTPUT_FILE, BAILIAN_API_KEY, MAX_WORKERS, VALIDATE_CORRECT_OUTPUT)
    end_time = time.time()
    
    print(f"\n处理完成！总耗时: {(end_time - start_time) / 60:.2f}分钟") 