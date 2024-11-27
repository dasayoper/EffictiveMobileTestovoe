CREATE TABLE IF NOT EXISTS account
(
    id         UUID PRIMARY KEY,
    state      VARCHAR(20) DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DELETED')),
    first_name VARCHAR(30)         NOT NULL CHECK (LENGTH(first_name) BETWEEN 2 AND 30),
    last_name  VARCHAR(30)         NOT NULL CHECK (LENGTH(last_name) BETWEEN 2 AND 30),
    email      VARCHAR(255) UNIQUE NOT NULL CHECK (email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'),
    password   VARCHAR(255)        NOT NULL,
    role       VARCHAR(20)         NOT NULL CHECK (role IN ('COMMON_USER', 'ADMIN'))
);

CREATE TABLE IF NOT EXISTS task
(
    id          UUID PRIMARY KEY,
    state       VARCHAR(20) DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DELETED')),
    title       VARCHAR(50) NOT NULL CHECK (LENGTH(title) BETWEEN 1 AND 50),
    description TEXT,
    status      VARCHAR(20) NOT NULL CHECK (status IN ('NEW', 'ASSIGNED', 'DISCUSSION', 'REVIEW', 'APPROVED', 'REJECTED', 'CLOSED')),
    priority    VARCHAR(20) NOT NULL CHECK (priority IN ('HIGH', 'MEDIUM', 'LOW')),
    author_id   UUID        REFERENCES account (id) ON DELETE SET NULL,
    executor_id UUID        REFERENCES account (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS comment
(
    id             UUID PRIMARY KEY,
    state          VARCHAR(20) DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DELETED')),
    text           VARCHAR(500) NOT NULL CHECK (LENGTH(text) BETWEEN 1 AND 500),
    author_id      UUID         REFERENCES account (id) ON DELETE SET NULL,
    task_id        UUID REFERENCES task (id) ON DELETE CASCADE,
    posted_at      TIMESTAMP    NOT NULL,
    last_edited_at TIMESTAMP    NOT NULL
);