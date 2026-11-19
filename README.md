# Лабораторна робота №4: Аутентифікація (JWT), RBAC та автотести у CI

REST API обліку витрат на Flask з PostgreSQL, ORM (SQLAlchemy), міграціями (Alembic), JWT-аутентифікацією, захистом паролів за Argon2id, рольовою моделлю доступу та автотестами з запуском у GitHub Actions.

## Індивідуальне завдання (з лабораторної №3)

Номер варіанта: `V = (N % 3) + 1`, де `N` — номер залікової книжки.

- N = 4208
- 4208 % 3 = 2 (4208 = 3 · 1402 + 2)
- V = 2 + 1 = **3**

Варіант 3: рахунки користувача (`Account`). Реалізовано поповнення рахунку (`POST /account/<id>/topup`) та автоматичне списання суми з балансу при створенні витрати (`POST /record`); якщо коштів не вистачає, повертається `400 insufficient_funds`.

## Аутентифікація

- `POST /register` — реєстрація (`{"name": "...", "password": "..."}`), роль за замовчуванням `user`.
- `POST /login` — перевірка облікових даних і видача Access JWT (термін дії 1 година), ролі передаються в claim `roles`.
- Токен передається в заголовку `Authorization: Bearer <Access Token>`.
- Відсутній, некоректний або прострочений токен: `401 Unauthorized`.
- Паролі зберігаються лише у вигляді хешів Argon2id (бібліотека `argon2-cffi`).

## Ролі та доступ

Недостатньо прав для дії: `403 Forbidden`. Спроба звернутися до чужих даних звичайним користувачем: `404 Not Found`.

| Ендпоінт | user | auditor | admin |
|---|---|---|---|
| `POST /register`, `POST /login`, `GET /healthz/live`, `GET /healthz/ready` | публічні | публічні | публічні |
| `GET /user/<id>` | лише свій | будь-який | будь-який |
| `GET /users` | 403 | читання | так |
| `DELETE /user/<id>`, `PATCH /user/<id>/role` | 403 | 403 | так |
| `POST /record` | свої | 403 | так |
| `GET /record/<id>` | лише свої | будь-які | будь-які |
| `DELETE /record/<id>` | лише свої | 403 | будь-які |
| `GET /record?user_id=X&category_id=Y` | лише свої | усі | усі |
| `GET /category` | глобальні та свої | усі | усі |
| `POST /category` | свої | 403 | так |
| `POST /category/global`, `DELETE /category/<id>` | 403 | 403 | так |
| `POST /account`, `POST /account/<id>/topup` | лише свій | 403 | будь-який |
| `GET /account/<id>` | лише свій | будь-який | будь-який |

## Запуск

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
docker compose up -d
flask --app app db upgrade
python app.py
```

Сервер доступний за адресою http://127.0.0.1:5000. Змінні середовища: `DATABASE_URL` (адреса бази) та `JWT_SECRET_KEY` (секрет підпису токенів).

Перший адміністратор створюється командою:

```
flask --app app create-admin <name> <password>
```

Решту ролей призначає адміністратор через `PATCH /user/<id>/role` (`{"role": "auditor"}`).

## Тестування

Тести використовують окрему базу `expenses_test`:

```
docker compose exec db psql -U expenses -d expenses -c "CREATE DATABASE expenses_test;"
pytest -v
```

Тести охоплюють реєстрацію, логін, хешування паролів, відсутній та некоректний токен (`401`), матрицю доступів усіх ролей (`403`/`404`), списання коштів з рахунку, а також перевірку часу за допомогою `freeze_time`.

## CI

У GitHub Actions (`.github/workflows/ci.yml`) під час кожного push запускається PostgreSQL 16 як service-контейнер, після чого виконується `pytest`.