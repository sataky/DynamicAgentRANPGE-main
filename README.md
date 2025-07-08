# App API - LLM Concurrent Learning Platform

A FastAPI-based backend application for an AI-powered learning platform with intelligent chat, evaluation, and document processing capabilities.

## 🏗️ Architecture
app/
├── api/ # API routes and endpoints
│ ├── auth_routes.py # Authentication endpoints
│ ├── chat_routes.py # Chat and conversation endpoints
│ ├── evaluation_routes.py # Evaluation and grading endpoints
│ ├── admin_routes.py # Admin and content management
│ └── users_routes.py # User management endpoints
├── models/ # Data models and schemas
│ ├── entities/ # Database entity models
│ └── schemas/ # Pydantic request/response schemas
├── services/ # Business logic services
│ ├── chat/ # Chat processing services
│ ├── evaluation/ # Evaluation and grading services
│ ├── database/ # Database operations
│ └── external/ # External API integrations
├── repositories/ # Data access layer
├── utils/ # Utility functions and helpers
├── logs/ # Application logs
├── config.py # Configuration and environment settings
├── state.py # Global application state management
└── main.py # FastAPI application entry point


## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- MongoDB
- Azure OpenAI account
- Azure Storage account (optional)

### Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables:**
   Create a `.env` file:
   ```env
   # MongoDB Configuration
   MONGO_URI=mongodb://localhost:27017
   MONGO_DB_CHAT=your_database_name

   # Azure OpenAI Configuration
   AZURE_OPENAI_ENDPOINT=your_azure_openai_endpoint
   AZURE_OPENAI_KEY=your_azure_openai_key
   AZURE_OPENAI_API_VERSION=2024-02-15-preview
   AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4=gpt-4
   AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4o=gpt-4o
   AZURE_OPENAI_MODEL_AND_DEPLOYMENT_4omini=gpt-4o-mini

   # Azure Storage Configuration (optional)
   AZURE_CONTAINER_NAME=your_container_name
   AZURE_STORAGE_CONNECTION_STRING=your_storage_connection_string

   # External Services
   GRADER_API_URL=http://localhost:8003
   TOOLS_DB_URL=http://localhost:3002/tools

   # JWT Configuration
   JWT_SECRET_KEY=your_jwt_secret_key
   JWT_ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   REFRESH_TOKEN_EXPIRE_DAYS=7
   ```

3. **Run the application:**
   ```bash
   # Development mode
   python -m app.main

   # Or directly
   python app/main.py
   ```

The API will be available at `http://localhost:8000`

## 📚 API Documentation

Once the server is running, access:
- **Interactive API docs (Swagger UI):** `http://localhost:8000/docs`
- **ReDoc documentation:** `http://localhost:8000/redoc`

## 🎯 Core Features

### 1. **Intelligent Chat System**
- **ReAct Agent**: Powered by LlamaIndex with tool-based reasoning
- **Conversation Memory**: Persistent chat history with MongoDB
- **Document Context**: Chat with knowledge from uploaded documents
- **Streaming Responses**: Real-time chat responses

### 2. **AI-Powered Evaluation**
- **Multiple Question Types**: Mixed, case-based, MCQ, and open questions
- **Intelligent Grading**: Azure OpenAI-powered evaluation
- **Batch Processing**: Concurrent evaluation handling
- **Score Tracking**: User performance monitoring

### 3. **Document Processing**
- **Multi-format Support**: PDF, DOCX, TXT files
- **Azure Storage Integration**: Scalable document storage
- **Document Indexing**: Automatic knowledge extraction
- **Tool Generation**: Dynamic tool creation from documents

### 4. **User Management**
- **JWT Authentication**: Secure token-based auth
- **User Profiles**: Comprehensive user data management
- **Score Tracking**: Performance analytics
- **Session Management**: Persistent user sessions

## 🔌 API Endpoints

### Authentication (`/api/auth`)
- `POST /api/auth/login` - User login with credentials
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user information
- `POST /api/auth/logout` - User logout

### Chat (`/api/chat`)
- `POST /api/chat/process` - Process chat message with AI
- `POST /api/chat/stream` - Stream chat responses
- `GET /api/chat/history` - Get conversation history
- `DELETE /api/chat/history` - Clear chat history

### Evaluation (`/api/evaluation`)
- `POST /api/evaluation/evaluate-mixed` - Mixed question evaluation
- `POST /api/evaluation/evaluate-case` - Case-based evaluation
- `POST /api/evaluation/mcq-or-open` - MCQ or open questions
- `POST /api/evaluation/submit-and-save` - Submit and save evaluation
- `POST /api/evaluation/submit-case-and-save` - Submit case evaluation

### Admin (`/api/admin`)
- `GET /api/admin/topics/by-program/{program}/{level}` - Get topics by program
- `GET /api/admin/topics/by-module/{course}/{module}` - Get topics by module
- `POST /api/admin/topics` - Create new topic
- `PUT /api/admin/topics/{topic_id}` - Update topic
- `DELETE /api/admin/topics/{topic_id}` - Delete topic

### Users (`/api/users`)
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users/scores` - Get user evaluation scores

## 🧠 AI Integration

### Azure OpenAI Models
- **GPT-4**: High-performance reasoning and analysis
- **GPT-4o**: Optimized for speed and efficiency
- **GPT-4o-mini**: Cost-effective for simple tasks

### Model Selection Strategy
- **Random Selection**: Automatic model rotation for evaluations
- **Load Balancing**: Distributed processing across models
- **Fallback Handling**: Graceful degradation on model failures

### LlamaIndex Integration
- **Query Engine Tools**: Dynamic tool generation from documents
- **ReAct Agent**: Tool-based reasoning for complex queries
- **Document Indexing**: Automatic knowledge extraction and indexing

## 🗄️ Data Models

### User Entity
```python
class UserModel:
    username: str
    email: str
    password_hash: str
    created_at: datetime
    last_login: datetime
    average_score: float
    evaluations: List[EvaluationScore]
```

### Chat Session
```python
class ChatSession:
    user_id: str
    conversation_id: str
    messages: List[ChatMessage]
    created_at: datetime
    updated_at: datetime
```

### Evaluation
```python
class EvaluationScore:
    score: float
    topics: List[str]
    evaluation_type: str
    date: datetime
```

## 🔧 Configuration

### Environment Variables
- **MongoDB**: Database connection and configuration
- **Azure OpenAI**: API credentials and model settings
- **Azure Storage**: Document storage configuration
- **External Services**: Grader API and tools database URLs
- **JWT**: Authentication token configuration

### Application Settings
- **Evaluation Batch Size**: 5 concurrent evaluations
- **Max Concurrent Evaluations**: 10 simultaneous requests
- **CORS**: Configured for cross-origin requests
- **Logging**: Structured logging with different levels

## 🚀 Performance Features

### Concurrent Processing
- **Async/Await**: Non-blocking I/O operations
- **Worker Management**: Efficient request handling
- **Connection Pooling**: Optimized database connections

### Caching Strategy
- **LRU Cache**: Model client caching
- **Session Storage**: User session data
- **Document Indexing**: Cached document tools

### Error Handling
- **Graceful Degradation**: Fallback mechanisms
- **Retry Logic**: Automatic retry for transient failures
- **Error Logging**: Comprehensive error tracking

## 🔒 Security

### Authentication & Authorization
- **JWT Tokens**: Secure token-based authentication
- **Password Hashing**: Secure password storage
- **Token Refresh**: Automatic token renewal
- **Session Management**: Secure session handling

### Data Protection
- **Input Validation**: Pydantic model validation
- **CORS Configuration**: Controlled cross-origin access
- **Environment Variables**: Secure configuration management

## 📊 Monitoring & Logging

### Application Logs
- **Structured Logging**: JSON-formatted log entries
- **Log Levels**: INFO, WARNING, ERROR, DEBUG
- **Log Rotation**: Automatic log file management

### Performance Monitoring
- **Request Tracking**: API endpoint performance
- **Error Monitoring**: Error rate and type tracking
- **Resource Usage**: Memory and CPU monitoring

## 🧪 Development

### Code Structure
- **Clean Architecture**: Separation of concerns
- **Dependency Injection**: Modular service design
- **Type Hints**: Full Python type annotations
- **Docstrings**: Comprehensive documentation

### Testing
```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=app tests/
```

### Code Quality
- **Linting**: flake8 and black formatting
- **Type Checking**: mypy static type checking
- **Documentation**: Auto-generated API docs

## 🚀 Deployment

### Production Configuration
- **Gunicorn**: WSGI server for production
- **Uvicorn Workers**: ASGI worker processes
- **Environment Variables**: Production configuration
- **Health Checks**: Application health monitoring

### Docker Support
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "-m", "app.main"]
```

## 🤝 Contributing

1. Follow the existing code structure and patterns
2. Use proper docstrings for all functions
3. Add appropriate error handling
4. Update API documentation when adding new endpoints
5. Test your changes thoroughly

## 📝 License

This project is proprietary and confidential.

---

**Note**: This application is part of a larger learning platform ecosystem. Ensure proper configuration of external services and frontend integration.