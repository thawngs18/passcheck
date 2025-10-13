import google.generativeai as genai
from config import Config

class AIService:
    def __init__(self):
        genai.configure(api_key=Config.GOOGLE_AI_API_KEY)
        # Sử dụng model mới nhất được hỗ trợ
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        
    def chat_with_ai(self, user_message, password_context=None):
        """Chat với AI về bảo mật mật khẩu"""
        
        # Tạo prompt context cho AI
        system_prompt = """
        Bạn là một chuyên gia bảo mật mật khẩu thông minh. 
        Nhiệm vụ của bạn là:
        1. Trả lời câu hỏi về bảo mật mật khẩu
        2. Tư vấn cách tạo mật khẩu mạnh
        3. Phân tích mật khẩu và đưa ra gợi ý cải thiện
        4. Giải thích các khái niệm bảo mật một cách dễ hiểu
        5. Sử dụng tiếng Việt tự nhiên và thân thiện
        
        Luôn đưa ra lời khuyên thực tế và dễ áp dụng.
        """
        
        # Thêm context về mật khẩu nếu có
        if password_context:
            context_info = f"""
            Thông tin mật khẩu hiện tại:
            - Độ dài: {password_context.get('length', 'N/A')} ký tự
            - Entropy: {password_context.get('entropy', 'N/A')} bits
            - Độ mạnh: {password_context.get('strength', 'N/A')}
            - Thời gian crack: {password_context.get('crack_time', 'N/A')}
            - Các vấn đề: {password_context.get('issues', 'Không có')}
            """
            system_prompt += context_info
        
        try:
            response = self.model.generate_content(
                f"{system_prompt}\n\nNgười dùng: {user_message}"
            )
            return response.text
        except Exception as e:
            return f"Xin lỗi, tôi gặp lỗi khi xử lý câu hỏi của bạn: {str(e)}"
    
    def generate_password_suggestion(self, requirements):
        """Tạo gợi ý mật khẩu dựa trên yêu cầu"""
        
        prompt = f"""
        Tạo gợi ý mật khẩu mạnh dựa trên yêu cầu:
        - Mục đích sử dụng: {requirements.get('purpose', 'Chung')}
        - Độ dài mong muốn: {requirements.get('length', '12-16')} ký tự
        - Sở thích cá nhân: {requirements.get('interests', 'Không có')}
        - Yêu cầu đặc biệt: {requirements.get('special', 'Không có')}
        
        Hãy tạo 3 mật khẩu mạnh và giải thích tại sao chúng an toàn.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Xin lỗi, tôi không thể tạo gợi ý mật khẩu: {str(e)}"
