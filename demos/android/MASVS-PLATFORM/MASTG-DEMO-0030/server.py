import http.server
import socketserver
import json

class Handler(http.server.BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)
        text = data.decode('utf-8')
        print(f'\n\n[*] Received POST data from {self.client_address[0]}:\n')
        try:
            parsed = json.loads(text)
            pretty = json.dumps(parsed, indent=4)
            print(pretty)
        except Exception as e:
            print(text)
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress the default logging
        pass

if __name__ == '__main__':
    with socketserver.TCPServer(('0.0.0.0', 5001), Handler) as httpd:
        print('Serving on port 5001...')
        httpd.serve_forever()
