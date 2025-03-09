from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        print(f"Path: {parsed_path.path}")
        print("GET Parameters:")
        result = ""
        for key, values in params.items():
            print(f"  {key}: {', '.join(values)}")
            result += f"  {key}: {', '.join(values)}\n"
        
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"GET request received\n" + bytes(result, 'utf-8'))
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        try:
            params = json.loads(post_data)  # 尝试解析 JSON 数据
        except json.JSONDecodeError:
            params = parse_qs(post_data)  # 解析表单格式的数据
        
        print(f"Path: {self.path}")
        print("POST Parameters:")
        result = ""
        for key, values in params.items():
            if isinstance(values, list):
                print(f"  {key}: {', '.join(values)}")
                result += f"  {key}: {', '.join(values)}\n"
            else:
                print(f"  {key}: {values}")
                result += f"  {key}: {values}\n"
        
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"POST request received\n" + bytes(result, 'utf-8'))

if __name__ == "__main__":
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Serving on port 8000...")
    httpd.serve_forever()
