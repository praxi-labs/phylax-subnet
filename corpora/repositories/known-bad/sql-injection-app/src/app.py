from db import get_user

def handle_request(request):
    name = request.get("name")
    return get_user(name)
