# TaskManager

## Локальный запуск проекта

Для локального запуска проекта необходимо использовать Docker Compose. Следуйте инструкциям ниже, чтобы настроить и запустить проект.

### Предварительные требования

1. Установите [Docker](https://www.docker.com/get-started).
2. Установите [Docker Compose](https://docs.docker.com/compose/install/).

### Настройка окружения

1. Склонируйте репозиторий:

    ```sh
    git clone <URL_репозитория>
    cd <имя_репозитория>
    ```

2. Создайте файл `.env` в корневом каталоге проекта (на уровне с файлом docker-compose.yaml) и добавьте в него следующие переменные окружения:

    ```env
    SERVER_PORT=80

    SPRING_DATASOURCE_DRIVER_CLASS_NAME=org.postgresql.Driver
    SPRING_DATASOURCE_USERNAME=your_db_username
    SPRING_DATASOURCE_PASSWORD=your_db_password
    SPRING_DATASOURCE_URL=jdbc:postgresql://database:5432/your_db_name

    SPRING_JPA_HIBERNATE_DDL_AUTO=update
    SPRING_JPA_SHOW_SQL=true
    SPRING_JPA_PROPERTIES_HIBERNATE_FORMAT_SQL=true
    SPRING_JPA_PROPERTIES_HIBERNATE_ENABLE_LAZY_LOAD_NO_TRANS=true

    SPRING_DATA_REDIS_HOST=redis
    SPRING_DATA_REDIS_PORT=6380

    JWT_SECRET=your_secret_key
    JWT_ACCESS_EXPIRATION=3600000
    JWT_REFRESH_EXPIRATION=604800000

    SPRINGDOC_SWAGGER_UI_PATH=/task-manager-documentation
    SPRINGDOC_API_DOCS_PATH=/v3/task-manager-api-docs

    APP_DOCKERFILE=your_path_to_/TaskManager
    REDIS_DOCKERFILE=your_path_to_/Redis

    POSTGRES_DB=your_db_name
    POSTGRES_USER=your_db_username
    POSTGRES_PASSWORD=your_db_password

    LOG_PATH=/usr/local/lib/logs
    
    COMPOSE_PROJECT_NAME=task_manager-api_project
    ```

   Замените `your_db_username`, `your_db_password`, `your_db_name`, и другие значения на соответствующие значения для вашего окружения.

### Запуск проекта

1. Запустите Docker Compose:

    ```sh
    docker-compose up --build
    ```

   Эта команда соберет образы и запустит контейнеры для приложения, базы данных и Redis.

2. Проверьте, что все контейнеры запущены:

    ```sh
    docker-compose ps
    ```

### Остановка проекта

Чтобы остановить и удалить все контейнеры, сети и тома, созданные с помощью Docker Compose, выполните следующую команду:

```sh
docker-compose down
