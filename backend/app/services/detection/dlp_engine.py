import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib

@dataclass
class DLPMatch:
    policy_id: int
    policy_name: str
    data_type: str
    channel: str
    action: str
    severity: str
    pattern: str
    matched_value: str
    location: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    file_name: Optional[str] = None

class DLPDetectionEngine:
    PREDEFINED_PATTERNS = {
        'credit_card': {
            'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'description': 'Credit Card Number',
            'validator': lambda x: luhn_check(x.replace('-', '').replace(' ', ''))
        },
        'ssn': {
            'pattern': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            'description': 'Social Security Number',
            'validator': None
        },
        'account_number': {
            'pattern': r'\b\d{8,17}\b',
            'description': 'Bank Account Number',
            'validator': None
        },
        'routing_number': {
            'pattern': r'\b\d{9}\b',
            'description': 'Routing Transit Number',
            'validator': lambda x: len(x) == 9 and x.isdigit()
        },
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email Address',
            'validator': None
        },
        'phone': {
            'pattern': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'description': 'Phone Number',
            'validator': None
        },
        'password': {
            'pattern': r'(?:password|passwd|pwd)[^\n]{0,50}',
            'description': 'Password Field',
            'validator': None
        },
        'api_key': {
            'pattern': r'(?:api[_-]?key|apikey|secret[_-]?key)[^\n]{0,50}',
            'description': 'API Key',
            'validator': None
        },
        'iban': {
            'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b',
            'description': 'IBAN',
            'validator': None
        },
    }

    def __init__(self):
        self.compiled_patterns = {}
        for name, config in self.PREDEFINED_PATTERNS.items():
            self.compiled_patterns[name] = re.compile(config['pattern'], re.IGNORECASE)

    def luhn_check(self, number: str) -> bool:
        def digits_of(n):
            return [int(d) for d in str(n)]
        digits = digits_of(number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return checksum % 10 == 0

    def scan_content(
        self,
        content: str,
        policies: List[Dict],
        user: Optional[str] = None,
        source_ip: Optional[str] = None,
        channel: str = 'web',
        file_name: Optional[str] = None
    ) -> List[DLPMatch]:
        matches = []
        
        for policy in policies:
            if not policy.get('enabled', True):
                continue
            
            data_type = policy.get('data_type')
            pattern = policy.get('pattern', '')
            
            try:
                if data_type in self.PREDEFINED_PATTERNS:
                    regex = self.compiled_patterns.get(data_type)
                    if regex:
                        for match in regex.finditer(content):
                            matched_value = match.group()
                            if data_type == 'credit_card':
                                validator = self.PREDEFINED_PATTERNS['credit_card']['validator']
                                if validator and not validator(matched_value):
                                    continue
                            matches.append(self._create_match(policy, matched_value, channel, user, source_ip, file_name))
                elif pattern:
                    regex = re.compile(pattern, re.IGNORECASE)
                    for match in regex.finditer(content):
                        matches.append(self._create_match(policy, match.group(), channel, user, source_ip, file_name))
            except re.error as e:
                print(f"Invalid regex pattern in policy {policy.get('name')}: {e}")
                continue
        
        return matches

    def _create_match(
        self,
        policy: Dict,
        matched_value: str,
        channel: str,
        user: Optional[str],
        source_ip: Optional[str],
        file_name: Optional[str]
    ) -> DLPMatch:
        masked_value = self._mask_sensitive(matched_value, policy.get('data_type', ''))
        
        return DLPMatch(
            policy_id=policy.get('id'),
            policy_name=policy.get('name', 'Unknown'),
            data_type=policy.get('data_type', 'custom'),
            channel=channel,
            action=policy.get('action', 'block'),
            severity=policy.get('severity', 'medium'),
            pattern=policy.get('pattern', ''),
            matched_value=masked_value,
            location='content',
            user=user,
            source_ip=source_ip,
            file_name=file_name
        )

    def _mask_sensitive(self, value: str, data_type: str) -> str:
        if data_type == 'credit_card':
            if len(value) >= 8:
                return value[:4] + '*' * (len(value) - 8) + value[-4:]
        elif data_type == 'ssn':
            if len(value) >= 4:
                return '***-**-' + value[-4:]
        elif data_type == 'password' or data_type == 'api_key':
            return '***'
        
        if len(value) > 4:
            return value[:2] + '*' * (len(value) - 4) + value[-2:]
        return '***'

    def scan_file(self, file_path: str, policies: List[Dict], **kwargs) -> List[DLPMatch]:
        import os
        
        if not os.path.exists(file_path):
            return []
        
        ext = os.path.splitext(file_path)[1].lower()
        
        try:
            if ext in ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.md']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    return self.scan_content(content, policies, file_name=os.path.basename(file_path), **kwargs)
            elif ext in ['.pdf', '.doc', '.docx']:
                return []
            else:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    try:
                        content = content.decode('utf-8', errors='ignore')
                    except:
                        content = str(content)
                    return self.scan_content(content, policies, file_name=os.path.basename(file_path), **kwargs)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []

    def get_available_data_types(self) -> Dict[str, str]:
        return {
            name: config['description']
            for name, config in self.PREDEFINED_PATTERNS.items()
        }


dlp_engine = DLPDetectionEngine()
