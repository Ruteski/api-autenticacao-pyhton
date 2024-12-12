# API de Autenticação com FastAPI e JWT

Esta é uma API de autenticação construída com FastAPI que implementa autenticação JWT (JSON Web Token) e controle de acesso baseado em papéis (RBAC). A API possui diferentes níveis de acesso para usuários normais e administradores.

## Funcionalidades

- Autenticação usando JWT
- Controle de acesso baseado em papéis (user e admin)
- Armazenamento seguro de senhas usando PBKDF2
- Banco de dados SQLite para persistência
- Rotas protegidas por autenticação
- Gerenciamento de usuários (listar)

## Requisitos

- Dependências listadas em `requirements.txt`

## Instalação

1. Clone o repositório:
```bash
git clone <url-do-repositorio>
cd <nome-do-diretorio>
```

2. Crie e ative um ambiente virtual:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Configuração

O projeto usa SQLite como banco de dados e criará automaticamente um arquivo `database.db` quando executado pela primeira vez. Os usuários padrão serão criados automaticamente:

- Usuário normal:
  - Username: user
  - Password: L0XuwPOdS5U
  - Role: user

- Usuário administrador:
  - Username: admin
  - Password: JKSipm0YH
  - Role: admin

## Executando o Projeto

1 . Ative o ambiente virtual conforme explicado anteriormente

2. Inicie o servidor:
```bash
windows: python main.py
linux/mac: python3 mani.py
```

O servidor estará disponível em `http://localhost:8000`

## Endpoints da API

### Autenticação

- **POST /token**
  - Gera um token JWT para um usuário válido
  - Body: form-data com `username` e `password`
  - Retorna: `access_token` e `token_type`

### Rotas Protegidas

- **GET /user**
  - Acessível por usuários e admins
  - Requer: Token JWT válido
  - Retorna: Mensagem de boas-vindas e dados do usuário

- **GET /admin**
  - Acessível apenas por admins
  - Requer: Token JWT válido de um admin
  - Retorna: Mensagem de boas-vindas e dados do admin

### Gerenciamento de Usuários

- **GET /users**
  - Lista todos os usuários
  - Acessível apenas por admins
  - Requer: Token JWT válido de um admin

## Exemplos de Uso

1. Obter token de acesso:
```bash
curl -X POST "http://localhost:8000/token" \
  -F "username=<usuario>" \
  -F "password=<senha>
```

2. Acessar rota protegida:
```bash
curl -H "Authorization: Bearer <seu_token>" \
  http://localhost:8000/user
```

## Estrutura do Projeto

- `main.py`: Arquivo principal da aplicação FastAPI
- `database.py`: Módulo de gerenciamento do banco de dados
- `requirements.txt`: Lista de dependências
- `database.db`: Banco de dados SQLite (criado automaticamente)

## Segurança

- Senhas são armazenadas usando hash PBKDF2
- Tokens JWT são usados para autenticação
- Controle de acesso baseado em papéis
- Proteção contra credenciais inválidas

## Notas de Desenvolvimento

Em um ambiente de produção, você deve:
1. Usar uma chave secreta segura para o JWT
2. Implementar HTTPS
3. Configurar logs apropriados
4. Implementar rate limiting
5. Considerar usar um banco de dados mais robusto

## Contribuindo

1. Faça um Fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.