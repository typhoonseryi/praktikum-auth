# Сервис запускается комадой docker-compose up --build
Параллельно запускаются тесты каждого эндпоинта.  
1. Документация Swagger доступна по URL http://localhost:8000/apidocs/  
2. Чувствительные данные записываются в файл flask_app/.env  
3. Конфигурация сервиса аутентификации представлена в файле flask_app/config.py, эндпоинты - в flask_app/auth_views.py  
4. Для запуска приложения используются команды из docker_entrypoint.sh. Для самостоятельного запуска приложения используйте следующие команды:
   - flask db upgrade
   - flask create_superuser
   - gunicorn -w 4 -b 0.0.0.0:8000 wsgi_app:app  
   
Над проектом работал Шуктомов Сергей
