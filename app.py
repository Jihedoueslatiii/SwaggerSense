from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import google.generativeai as genai
import requests
import json
import time
import logging
import re
from datetime import datetime
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

GEMINI_API_KEY = "AIzaSyAaVgNCZPXkkdNZOHIVR03u-dgmJ0uAvcg"
genai.configure(api_key=GEMINI_API_KEY)

class AdaptiveAPITester:
    """AI-Powered Adaptive API Tester that learns from your API"""
    
    def __init__(self, swagger_url: str, auth_token: str = ""):
        self.swagger_url = swagger_url
        self.auth_token = auth_token
        self.openapi_spec = None
        self.endpoints = []
        
    def fetch_swagger_spec(self) -> Dict:
        """Fetch OpenAPI/Swagger specification"""
        try:
            logger.info(f"Fetching API spec from: {self.swagger_url}")
            response = requests.get(self.swagger_url, timeout=10)
            response.raise_for_status()
            self.openapi_spec = response.json()
            logger.info("Successfully fetched OpenAPI specification")
            
            return {
                'success': True,
                'spec': self.openapi_spec,
                'info': self.openapi_spec.get('info', {}),
                'servers': self.openapi_spec.get('servers', [])
            }
        except Exception as e:
            logger.error(f"Failed to fetch spec: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def parse_openapi_spec(self) -> List[Dict]:
        """Extract endpoints and schemas from OpenAPI spec"""
        if not self.openapi_spec:
            return []
        
        endpoints = []
        paths = self.openapi_spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    endpoint_data = {
                        'path': path,
                        'method': method.upper(),
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'parameters': details.get('parameters', []),
                        'requestBody': details.get('requestBody', {}),
                        'responses': details.get('responses', {}),
                        'tags': details.get('tags', []),
                        'security': details.get('security', [])
                    }
                    endpoints.append(endpoint_data)
        
        self.endpoints = endpoints
        logger.info(f"Parsed {len(endpoints)} endpoints")
        return endpoints
    
    def analyze_endpoint_deeply(self, endpoint: Dict) -> str:
        """Create a detailed analysis of the endpoint for AI"""
        
        path = endpoint['path']
        method = endpoint['method']
        summary = endpoint.get('summary', 'N/A')
        description = endpoint.get('description', 'N/A')
        tags = ', '.join(endpoint.get('tags', ['general']))
        path_params = [x for x in re.findall(r'\{(\w+)\}', path)]
        has_params = 'Yes' if '{' in path else 'No'
        security = endpoint.get('security', [])
        has_auth = 'Yes' if security else 'No'
        
        request_body = json.dumps(endpoint.get('requestBody', {}), indent=2)
        response_schema = json.dumps(endpoint.get('responses', {}), indent=2)
        parameters = json.dumps(endpoint.get('parameters', []), indent=2)
        
        analysis = f"""
ENDPOINT ANALYSIS FOR INTELLIGENT TEST GENERATION:

1. ENDPOINT DETAILS:
   - Path: {path}
   - Method: {method}
   - Summary: {summary}
   - Description: {description}
   - Tags: {tags}

2. PATH ANALYSIS:
   - Path segments: {path.split('/')}
   - Has path parameters: {has_params}
   - Path parameters: {path_params}

3. REQUEST SCHEMA:
{request_body}

4. RESPONSE SCHEMA:
{response_schema}

5. PARAMETERS:
{parameters}

6. SECURITY:
   - Requires auth: {has_auth}
   - Security schemes: {security}

TASK: Based on this detailed analysis, generate 12 highly personalized test scenarios that:
- Match the actual endpoint purpose and function
- Test realistic business logic for this specific API
- Include edge cases relevant to the data types and constraints
- Test proper HTTP status codes for this endpoint
- Consider the endpoint's relationship in the API
- Generate realistic payloads based on field names and types
- Test boundary conditions and constraints
- Include authentication/authorization tests if needed

Generate ONLY valid JSON array with this exact structure for each test:
{{
  "name": "Descriptive test name",
  "description": "What this test validates",
  "category": "Functionality|Security|Validation|EdgeCase|Performance|BusinessLogic",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "test_type": "functionality|security|validation|edge_case|performance|business_logic",
  "method": "{method}",
  "path": "{path}",
  "payload": {{}},
  "expected_status": [200],
  "should_pass": true,
  "tags": ["tag1", "tag2"]
}}

Return ONLY the JSON array, no markdown, no explanations. Start with [ and end with ]
"""
        
        return analysis
    
    def call_gemini_api_adaptive(self, endpoint: Dict) -> Dict:
        """Call Gemini with adaptive, context-aware prompt"""
        try:
            logger.info("Starting adaptive test generation...")
            
            # Get detailed analysis
            analysis = self.analyze_endpoint_deeply(endpoint)
            
            logger.info("Sending to Gemini AI...")
            model = genai.GenerativeModel('gemini-2.5-flash')
            
            response = model.generate_content(
                analysis,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,  # Lower temp for consistency
                    top_k=40,
                    top_p=0.95,
                    max_output_tokens=8192,
                )
            )
            
            if not response.text:
                logger.error("Empty response from Gemini")
                return {'success': False, 'error': 'Empty response'}
            
            generated_text = response.text.strip()
            logger.info(f"Generated {len(generated_text)} chars of test scenarios")
            
            # Extract JSON
            if '```json' in generated_text:
                generated_text = generated_text.split('```json')[1].split('```')[0].strip()
            elif '```' in generated_text:
                generated_text = generated_text.split('```')[1].split('```')[0].strip()
            
            json_start = generated_text.find('[')
            json_end = generated_text.rfind(']')
            
            if json_start < 0 or json_end <= json_start:
                logger.error("No JSON array found")
                return {'success': False, 'error': 'Invalid response format'}
            
            json_str = generated_text[json_start:json_end + 1]
            
            # Clean JSON
            json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
            json_str = json_str.replace("'", '"')
            json_str = ''.join(c for c in json_str if ord(c) >= 32 or c in '\n\r\t')
            
            # Parse with recovery
            try:
                test_scenarios = json.loads(json_str)
                logger.info(f"✓ Parsed {len(test_scenarios)} adaptive test scenarios")
            except json.JSONDecodeError as e:
                logger.warning(f"Parse failed, attempting recovery...")
                test_scenarios = None
                
                try:
                    lines = json_str.split('\n')
                    for i in range(len(lines), 0, -1):
                        attempt = '\n'.join(lines[:i]).rstrip(',').rstrip()
                        if attempt.endswith('}'):
                            attempt += ']'
                        try:
                            test_scenarios = json.loads(attempt)
                            logger.info(f"✓ Recovery successful")
                            break
                        except:
                            continue
                except:
                    pass
                
                if not test_scenarios:
                    logger.warning("Recovery failed, using intelligent fallback")
                    test_scenarios = self.create_intelligent_fallback(endpoint)
            
            # Validate and enhance
            for test in test_scenarios:
                self._ensure_test_fields(test, endpoint)
            
            return {'success': True, 'test_scenarios': test_scenarios}
            
        except Exception as e:
            logger.error(f"Adaptive generation error: {str(e)}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    def create_intelligent_fallback(self, endpoint: Dict) -> List[Dict]:
        """Generate intelligent fallback tests based on endpoint analysis"""
        method = endpoint.get('method', 'POST')
        path = endpoint.get('path', '/')
        summary = endpoint.get('summary', '')
        
        # Analyze what this endpoint likely does
        is_create = method == 'POST'
        is_read = method == 'GET'
        is_update = method in ['PUT', 'PATCH']
        is_delete = method == 'DELETE'
        
        tests = []
        
        # Base functionality test
        if is_create:
            tests.append({
                "name": "Valid Creation",
                "description": f"Create a new resource with valid data",
                "category": "Functionality",
                "severity": "MEDIUM",
                "test_type": "functionality",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [201, 200],
                "should_pass": True,
                "tags": ["smoke", "positive"]
            })
        elif is_read:
            tests.append({
                "name": "Valid Read",
                "description": f"Read existing resource",
                "category": "Functionality",
                "severity": "MEDIUM",
                "test_type": "functionality",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [200],
                "should_pass": True,
                "tags": ["smoke", "positive"]
            })
        elif is_update:
            tests.append({
                "name": "Valid Update",
                "description": f"Update resource with valid data",
                "category": "Functionality",
                "severity": "MEDIUM",
                "test_type": "functionality",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [200, 204],
                "should_pass": True,
                "tags": ["smoke", "positive"]
            })
        elif is_delete:
            tests.append({
                "name": "Valid Delete",
                "description": f"Delete existing resource",
                "category": "Functionality",
                "severity": "MEDIUM",
                "test_type": "functionality",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [200, 204],
                "should_pass": True,
                "tags": ["smoke", "positive"]
            })
        
        # Security tests
        tests.extend([
            {
                "name": "SQL Injection",
                "description": "Test SQL injection vulnerability",
                "category": "Security",
                "severity": "CRITICAL",
                "test_type": "security",
                "method": method,
                "path": path,
                "payload": {"input": "1' OR '1'='1", "name": "'; DROP TABLE--"},
                "expected_status": [400, 403],
                "should_pass": False,
                "tags": ["security", "critical"]
            },
            {
                "name": "XSS Attack",
                "description": "Test XSS vulnerability",
                "category": "Security",
                "severity": "CRITICAL",
                "test_type": "security",
                "method": method,
                "path": path,
                "payload": {"name": "<script>alert('xss')</script>"},
                "expected_status": [400, 403],
                "should_pass": False,
                "tags": ["security", "critical"]
            }
        ])
        
        # Validation tests
        tests.extend([
            {
                "name": "Missing Required Fields",
                "description": "Submit without required fields",
                "category": "Validation",
                "severity": "HIGH",
                "test_type": "validation",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [400],
                "should_pass": False,
                "tags": ["validation"]
            },
            {
                "name": "Invalid Data Types",
                "description": "Send wrong data types",
                "category": "Validation",
                "severity": "MEDIUM",
                "test_type": "validation",
                "method": method,
                "path": path,
                "payload": {"id": "not-a-number", "age": "not-a-number", "count": "abc"},
                "expected_status": [400],
                "should_pass": False,
                "tags": ["validation"]
            }
        ])
        
        # Edge cases
        tests.extend([
            {
                "name": "Empty Payload",
                "description": "Send empty request body",
                "category": "EdgeCase",
                "severity": "MEDIUM",
                "test_type": "edge_case",
                "method": method,
                "path": path,
                "payload": {},
                "expected_status": [400, 422],
                "should_pass": False,
                "tags": ["edge-case"]
            },
            {
                "name": "Null Values",
                "description": "Send null values in payload",
                "category": "EdgeCase",
                "severity": "LOW",
                "test_type": "edge_case",
                "method": method,
                "path": path,
                "payload": {"data": None, "name": None},
                "expected_status": [400, 422],
                "should_pass": False,
                "tags": ["edge-case"]
            }
        ])
        
        logger.info(f"✓ Generated {len(tests)} intelligent fallback tests")
        return tests
    
    def _ensure_test_fields(self, test: Dict, endpoint: Dict):
        """Ensure all required fields exist"""
        test.setdefault('name', 'Test')
        test.setdefault('description', 'Test scenario')
        test.setdefault('category', 'Functionality')
        test.setdefault('severity', 'MEDIUM')
        test.setdefault('test_type', 'functionality')
        test.setdefault('method', endpoint.get('method', 'GET'))
        test.setdefault('path', endpoint.get('path', '/'))
        test.setdefault('payload', {})
        test.setdefault('expected_status', [200])
        test.setdefault('should_pass', True)
        test.setdefault('tags', [])
    
    def execute_test(self, test_case: Dict, base_url: str) -> Dict:
        """Execute a single test case"""
        start_time = time.time()
        
        try:
            path = test_case['path']
            original_path = path
            test_path = path
            
            if '{' in test_path:
                test_path = re.sub(r'\{(\w+)\}', '123', test_path)
            
            test_path = test_path.replace('//', '/')
            
            if base_url.endswith('/') and test_path.startswith('/'):
                url = base_url[:-1] + test_path
            elif not base_url.endswith('/') and not test_path.startswith('/'):
                url = base_url + '/' + test_path
            else:
                url = base_url + test_path
            
            method = test_case['method']
            payload = test_case.get('payload')
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Adaptive-API-Tester/1.0'
            }
            
            if self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            
            request_kwargs = {
                'method': method,
                'url': url,
                'headers': headers,
                'timeout': 15,
                'allow_redirects': False
            }
            
            if payload and method in ['POST', 'PUT', 'PATCH']:
                request_kwargs['json'] = payload
            
            logger.info(f"Executing: {method} {url}")
            response = requests.request(**request_kwargs)
            elapsed = time.time() - start_time
            
            expected_status = test_case.get('expected_status', [])
            actual_status = response.status_code
            passed = actual_status in expected_status if expected_status else actual_status < 500
            
            return {
                'test_name': test_case['name'],
                'description': test_case['description'],
                'category': test_case['category'],
                'severity': test_case['severity'],
                'test_type': test_case['test_type'],
                'method': method,
                'endpoint': original_path,
                'test_endpoint': test_path,
                'payload': payload,
                'expected_status': expected_status,
                'actual_status': actual_status,
                'response_time': elapsed,
                'passed': passed,
                'should_pass': test_case.get('should_pass', True),
                'tags': test_case.get('tags', []),
                'timestamp': datetime.now().isoformat(),
                'success': True
            }
            
        except Exception as e:
            elapsed = time.time() - start_time
            return {
                'test_name': test_case['name'],
                'description': test_case['description'],
                'category': test_case['category'],
                'severity': test_case['severity'],
                'method': test_case.get('method', 'GET'),
                'endpoint': test_case.get('path', '/'),
                'error': str(e),
                'response_time': elapsed,
                'passed': False,
                'success': False,
                'timestamp': datetime.now().isoformat()
            }

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/fetch-swagger', methods=['POST'])
def fetch_swagger():
    data = request.json
    swagger_url = data.get('swaggerUrl', '').strip()
    auth_token = data.get('authToken', '').strip()
    
    if not swagger_url:
        return jsonify({'error': 'Swagger URL is required'}), 400
    
    try:
        tester = AdaptiveAPITester(swagger_url, auth_token)
        result = tester.fetch_swagger_spec()
        if not result['success']:
            return jsonify(result), 400
        endpoints = tester.parse_openapi_spec()
        
        return jsonify({
            'success': True,
            'spec_info': result['info'],
            'servers': result['servers'],
            'endpoints': endpoints,
            'total_endpoints': len(endpoints)
        })
    except Exception as e:
        logger.error(f"Swagger fetch failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/generate-tests', methods=['POST'])
def generate_tests():
    data = request.json
    endpoint = data.get('endpoint', {})
    
    if not endpoint:
        return jsonify({'error': 'Endpoint data required'}), 400
    
    try:
        tester = AdaptiveAPITester('', '')
        result = tester.call_gemini_api_adaptive(endpoint)
        
        if not result['success']:
            return jsonify(result), 400
        
        return jsonify({
            'success': True,
            'test_scenarios': result['test_scenarios'],
            'total_tests': len(result['test_scenarios'])
        })
    except Exception as e:
        logger.error(f"Test generation failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/run-tests', methods=['POST'])
def run_tests():
    data = request.json
    base_url = data.get('baseUrl', '').strip()
    auth_token = data.get('authToken', '').strip()
    test_scenarios = data.get('testScenarios', [])
    
    if not base_url or not test_scenarios:
        return jsonify({'error': 'Base URL and test scenarios required'}), 400
    
    try:
        tester = AdaptiveAPITester('', auth_token)
        results = []
        
        for i, test in enumerate(test_scenarios):
            logger.info(f"Test {i+1}/{len(test_scenarios)}")
            result = tester.execute_test(test, base_url)
            results.append(result)
            time.sleep(0.1)
        
        total = len(results)
        passed = len([r for r in results if r.get('passed', False)])
        failed = total - passed
        critical_count = len([r for r in results if r.get('severity') == 'CRITICAL' and not r.get('passed', False)])
        
        return jsonify({
            'success': True,
            'results': results,
            'statistics': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'success_rate': round((passed / total * 100), 2) if total > 0 else 0,
                'critical_count': critical_count
            }
        })
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'Adaptive API Tester',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')