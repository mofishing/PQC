#!/usr/bin/env python3
"""
Java Transformation String Parser
解析 Java Cipher.getInstance() 的 transformation 字符串

支持格式:
- "AES" → algorithm=AES
- "AES/CBC/PKCS5Padding" → algorithm=AES, mode=CBC, padding=PKCS5Padding
- "RSA/ECB/OAEPPadding" → algorithm=RSA, mode=ECB, padding=OAEPPadding
"""

import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TransformationInfo:
    """Java Cipher transformation 信息"""
    algorithm: str              # 算法名称 (e.g., "AES", "RSA")
    mode: Optional[str] = None  # 模式 (e.g., "CBC", "GCM", "ECB")
    padding: Optional[str] = None  # 填充 (e.g., "PKCS5Padding", "NoPadding")
    
    def to_profile_id(self) -> str:
        """转换为 profile_id"""
        # 标准化算法名称
        algo_upper = self.algorithm.upper()
        
        # 特殊映射
        algo_map = {
            'AES': 'ALG.AES',
            'DES': 'ALG.DES',
            'DESEDE': 'ALG.3DES',
            'TRIPLEDES': 'ALG.3DES',
            'RSA': 'ALG.RSA',
            'DSA': 'ALG.DSA',
            'DH': 'ALG.DH',
            'DIFFIEHELLMAN': 'ALG.DH',
            'ECDSA': 'ALG.ECDSA',
            'ECDH': 'ALG.ECDH',
            'RC4': 'ALG.RC4',
            'RC2': 'ALG.RC2',
            'CHACHA20': 'ALG.CHACHA20',
            'CHACHA20-POLY1305': 'ALG.CHACHA20_POLY1305',
        }
        
        return algo_map.get(algo_upper, f'ALG.{algo_upper}')


class JavaTransformationParser:
    """
    Java Cipher transformation 字符串解析器
    
    使用示例:
        parser = JavaTransformationParser()
        info = parser.parse("AES/CBC/PKCS5Padding")
        # TransformationInfo(algorithm='AES', mode='CBC', padding='PKCS5Padding')
    """
    
    def parse(self, transformation: str) -> Optional[TransformationInfo]:
        """
        解析 transformation 字符串
        
        Args:
            transformation: Cipher.getInstance() 的参数
                           (e.g., "AES", "AES/CBC/PKCS5Padding")
        
        Returns:
            TransformationInfo 或 None (如果解析失败)
        """
        if not transformation:
            return None
        
        transformation = transformation.strip().strip('"').strip("'")
        
        # 去除字符串字面量标记
        if transformation.startswith('"') and transformation.endswith('"'):
            transformation = transformation[1:-1]
        
        # 分割 transformation 字符串
        # 格式: algorithm/mode/padding
        parts = transformation.split('/')
        
        if len(parts) == 1:
            # 只有算法名称: "AES"
            return TransformationInfo(algorithm=parts[0].strip())
        elif len(parts) == 3:
            # 完整格式: "AES/CBC/PKCS5Padding"
            return TransformationInfo(
                algorithm=parts[0].strip(),
                mode=parts[1].strip() if parts[1].strip() else None,
                padding=parts[2].strip() if parts[2].strip() else None
            )
        elif len(parts) == 2:
            # 两部分: "AES/CBC" 或 "RSA/OAEP"
            # 需要判断第二部分是mode还是padding
            second_part = parts[1].strip().upper()
            
            # 已知模式列表
            known_modes = {'ECB', 'CBC', 'CTR', 'GCM', 'CCM', 'CFB', 'OFB', 'XTS'}
            
            if second_part in known_modes:
                return TransformationInfo(
                    algorithm=parts[0].strip(),
                    mode=parts[1].strip()
                )
            else:
                # 假设是 padding
                return TransformationInfo(
                    algorithm=parts[0].strip(),
                    padding=parts[1].strip()
                )
        
        return None
    
    def parse_keygen_algorithm(self, algorithm: str) -> Optional[str]:
        """
        解析 KeyGenerator.getInstance() 的 algorithm 参数
        
        Args:
            algorithm: KeyGenerator 算法名称 (e.g., "AES", "RSA", "DES")
        
        Returns:
            profile_id (e.g., "ALG.AES") 或 None
        """
        if not algorithm:
            return None
        
        algorithm = algorithm.strip().strip('"').strip("'")
        
        # 直接转换为 TransformationInfo
        info = TransformationInfo(algorithm=algorithm)
        return info.to_profile_id()
    
    def extract_from_string_literal(self, code_line: str) -> Optional[str]:
        """
        从代码行中提取字符串字面量
        
        例如:
            'Cipher.getInstance("AES/CBC/PKCS5Padding")' 
            → "AES/CBC/PKCS5Padding"
        
        Args:
            code_line: Java 代码行
        
        Returns:
            字符串字面量内容或 None
        """
        # 匹配双引号字符串
        match = re.search(r'"([^"]+)"', code_line)
        if match:
            return match.group(1)
        
        # 匹配单引号字符串
        match = re.search(r"'([^']+)'", code_line)
        if match:
            return match.group(1)
        
        return None


def test_parser():
    """测试解析器"""
    parser = JavaTransformationParser()
    
    test_cases = [
        ("AES", "AES only"),
        ("AES/CBC/PKCS5Padding", "AES with CBC and padding"),
        ("AES/GCM/NoPadding", "AES with GCM"),
        ("DESede/CBC/PKCS5Padding", "3DES with CBC"),
        ("RSA/ECB/PKCS1Padding", "RSA with ECB"),
        ("RSA/ECB/OAEPPadding", "RSA with OAEP"),
        ('"AES/CBC/PKCS5Padding"', "With quotes"),
    ]
    
    print("Java Transformation Parser Test")
    print("=" * 80)
    
    for transformation, description in test_cases:
        info = parser.parse(transformation)
        if info:
            print(f"\n{description}")
            print(f"  Input:  {transformation}")
            print(f"  Algorithm: {info.algorithm}")
            print(f"  Mode:      {info.mode}")
            print(f"  Padding:   {info.padding}")
            print(f"  Profile:   {info.to_profile_id()}")
        else:
            print(f"\n✗ Failed to parse: {transformation}")
    
    # 测试从代码行提取
    print("\n" + "=" * 80)
    print("Extract from code line:")
    code_lines = [
        'Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");',
        'KeyGenerator keyGen = KeyGenerator.getInstance("AES");',
    ]
    
    for line in code_lines:
        extracted = parser.extract_from_string_literal(line)
        print(f"\nCode:      {line}")
        print(f"Extracted: {extracted}")
        if extracted:
            info = parser.parse(extracted)
            if info:
                print(f"Profile:   {info.to_profile_id()}")


if __name__ == "__main__":
    test_parser()
