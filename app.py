from flask import Flask, render_template, request, jsonify
from ai_service import AIService

app = Flask(__name__)

# Initialize AI service
ai_service = AIService()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat_with_ai():
    """API endpoint cho AI Chat"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        password_context = data.get('password_context', None)
        
        if not user_message:
            return jsonify({'error': 'Tin nhắn không được để trống'}), 400
        
        # Gọi AI service
        ai_response = ai_service.chat_with_ai(user_message, password_context)
        
        return jsonify({
            'success': True,
            'response': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi xử lý: {str(e)}'
        }), 500

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    """API endpoint để tạo gợi ý mật khẩu"""
    try:
        data = request.get_json()
        requirements = data.get('requirements', {})
        
        # Gọi AI service để tạo gợi ý
        ai_response = ai_service.generate_password_suggestion(requirements)
        
        return jsonify({
            'success': True,
            'suggestions': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Lỗi tạo mật khẩu: {str(e)}'
        }), 500

if __name__ == '__main__':
    print("\nTruy cập: http://localhost:5000")
    app.run(debug=True)
