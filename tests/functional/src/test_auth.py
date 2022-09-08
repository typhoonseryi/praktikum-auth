import http

import pytest

from conftest import SERVICE_URL

pytestmark = pytest.mark.asyncio


async def test_register(session):
    # Создание пользователя с ошибкой валидации
    url = SERVICE_URL + "/api/v1/register"
    data = {"email": "defmail.ru", "password": "123"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.BAD_REQUEST

    # Создание пользователя без ошибок
    data["email"] = "def@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Создание пользователя повторное
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CONFLICT


async def test_login(session):
    # Логин с ошибкой валидации
    url = SERVICE_URL + "/api/v1/login"
    data = {"email": "defmail.ru", "password": "123"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.BAD_REQUEST

    # Логин с неверными учетными данными
    data["email"] = "abc@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.UNAUTHORIZED

    # Логин без ошибок
    data["email"] = "def@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_login_change(session):
    # Изменение логина с ошибкой валидации
    url = SERVICE_URL + "/api/v1/login/change"
    data = {"email": "ghimail.ru", "password": "123"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.BAD_REQUEST

    # Изменение логина с занятым логином
    data["email"] = "123@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CONFLICT

    # Изменение логина успешное
    data["email"] = "ghi@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Проверка логина с новым логином
    url = SERVICE_URL + "/api/v1/login"
    data["password"] = "123"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_password_reset(session):
    # Изменение пароля успешное
    url = SERVICE_URL + "/api/v1/reset"
    data = {"password": "456"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Проверка логина с новым паролем
    url = SERVICE_URL + "/api/v1/login"
    data["email"] = "ghi@mail.ru"
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_lk_history(session):
    # Проверка количества выводимых входов в учетную запись
    url = SERVICE_URL + "/api/v1/lk/history"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.OK
        assert len(await response.json()) == 3


async def test_refresh(session):
    # Проверка рефреша токенов
    url = SERVICE_URL + "/api/v1/refresh"
    async with session.post(url) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_logout(session):
    # Проверка выхода из учетной записи
    url = SERVICE_URL + "/api/v1/logout"
    async with session.delete(url) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Запрет доступа к защищенному эндпоинту при логауте
    url = SERVICE_URL + "/api/v1/lk/history"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.UNAUTHORIZED


async def test_create_role(session):
    # Логин под пользователем
    url = SERVICE_URL + "/api/v1/login"
    data = {"email": "ghi@mail.ru", "password": "456"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Проверка пользователя на роль админа
    url = SERVICE_URL + "/api/v1/roles"
    data = {"name": "admin", "description": "Admin privillegies"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.FORBIDDEN

    # Логин под админом
    url = SERVICE_URL + "/api/v1/login"
    data = {"email": "123@mail.ru", "password": "123"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Имя роли занято
    url = SERVICE_URL + "/api/v1/roles"
    data = {"name": "admin", "description": "Admin privillegies"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CONFLICT

    # Невалидные входные данные
    data = {"name": "", "description": ""}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.BAD_REQUEST

    # Успешное создание роли
    data = {"name": "subscriber"}
    async with session.post(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_get_roles(session):
    # Проверка количества созданных ролей
    url = SERVICE_URL + "/api/v1/roles"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.OK
        assert len(await response.json()) == 2


async def test_update_role(session):
    # Определение id роли
    url = SERVICE_URL + "/api/v1/roles"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.OK
        roles = await response.json()
        role_id = roles[1]["id"]

    # Имя роли занято
    url = SERVICE_URL + "/api/v1/roles/" + role_id
    data = {"name": "admin"}
    async with session.put(url, json=data) as response:
        assert response.status == http.HTTPStatus.CONFLICT

    # Обновление роли успешно
    data = {"name": "follower"}
    async with session.put(url, json=data) as response:
        assert response.status == http.HTTPStatus.CREATED


async def test_delete_role(session):
    # Определение id роли
    url = SERVICE_URL + "/api/v1/roles"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.OK
        roles = await response.json()
        role_id = roles[1]["id"]

    # Удаление роли
    url = SERVICE_URL + "/api/v1/roles/" + role_id
    async with session.delete(url) as response:
        assert response.status == http.HTTPStatus.CREATED

    # Количество ролей уменьшилось
    url = SERVICE_URL + "/api/v1/roles"
    async with session.get(url) as response:
        assert response.status == http.HTTPStatus.OK
        assert len(await response.json()) == 1
