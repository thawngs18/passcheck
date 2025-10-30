import google.generativeai as genai
from config import Config

class AIService:
    def __init__(self):
        genai.configure(api_key=Config.GOOGLE_AI_API_KEY)
        # Sử dụng model mới nhất được hỗ trợ
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        
    def chat_with_ai(self, user_message, password_context=None):
        """Chat với AI về bảo mật mật khẩu"""
        
        # Tạo prompt context cho AI - NGẮN GỌN HƠN
        system_prompt = """
        Bạn là chuyên gia bảo mật mật khẩu. Trả lời NGẮN GỌN, XÚC TÍCH:
        
        NGUYÊN TẮC TRẢ LỜI:
        - Tối đa 3-4 câu ngắn hoặc 3-4 gạch đầu dòng
        - Đi thẳng vào vấn đề, không dài dòng
        - Ưu tiên thông tin quan trọng nhất
        - Dùng bullet points (-) thay vì đoạn văn dài
        - Không lặp lại câu hỏi
        - Không giải thích quá chi tiết trừ khi được yêu cầu
        
        VÍ DỤ CÁCH TRẢ LỜI TỐT:
        Câu hỏi: "Làm thế nào để tạo mật khẩu mạnh?"
        Trả lời: 
        - Tối thiểu 12 ký tự
        - Kết hợp chữ hoa, thường, số, ký tự đặc biệt
        - Không dùng thông tin cá nhân
        - Dùng password manager để lưu
        """
        
        # Thêm context về mật khẩu nếu có - RÚT GỌN
        if password_context:
            context_info = f"""
            
            [Mật khẩu hiện tại: {password_context.get('length')} ký tự, {password_context.get('entropy')} bits, {password_context.get('strength')}]
            """
            system_prompt += context_info
        
        try:
            # Thêm generation config để giới hạn độ dài
            response = self.model.generate_content(
                f"{system_prompt}\n\nCâu hỏi: {user_message}\n\nTrả lời ngắn gọn:",
                generation_config={
                    'temperature': 0.7,
                    'max_output_tokens': 250,  # Giới hạn độ dài output
                }
            )
            return response.text
        except Exception as e:
            return f"Lỗi: {str(e)}"
    
    def generate_password_suggestion(self, requirements):
        """Tạo gợi ý mật khẩu dựa trên yêu cầu - NGẮN GỌN"""
        
        prompt = f"""
        Tạo 3 mật khẩu mạnh cho: {requirements.get('purpose', 'mục đích chung')}
        Độ dài: {requirements.get('length', '12-16')} ký tự
        
        Chỉ liệt kê 3 mật khẩu và 1 câu giải thích ngắn cho mỗi mật khẩu.
        Định dạng:
        1. [mật khẩu] - [1 câu giải thích ngắn]
        2. [mật khẩu] - [1 câu giải thích ngắn]
        3. [mật khẩu] - [1 câu giải thích ngắn]
        """
        
        try:
            response = self.model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.8,
                    'max_output_tokens': 300,
                }
            )
            return response.text
        except Exception as e:
            return f"Lỗi: {str(e)}"