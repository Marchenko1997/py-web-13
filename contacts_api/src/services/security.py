from fastapi.security import OAuth2PasswordBearer, HTTPBearer

API_PREFIX = "/api"


oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{API_PREFIX}/auth/login")


http_bearer = HTTPBearer()
