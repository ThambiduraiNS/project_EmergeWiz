
# project_EmergeWiz

## 1. Clone the repository

```bash
git clone https://github.com/ThambiduraiNS/project_EmergeWiz.git
```

## 2. Set up a virtual environment

```bash
python -m venv venv
venv\Scripts\activate  # On Ubuntu use: source venv/bin/activate
cd .\Ewiz_project\
```

## 3. Install the dependencies

```bash
pip install -r requirements.txt
```

## 4. Apply migrations

```bash
python manage.py migrate
```

## 6. Create a superuser

```bash
python manage.py createsuperuser
```

## 7. Run the development server

```bash
python manage.py runserver
```

## Project Structure

```
Ewiz_project/
├── Ewiz_app/                 # Main Django app
│   ├── migrations/           # Database migrations
│   ├── templates/            # HTML templates
│   ├── static/               # Static files (CSS, JS)
│   ├── models.py             # Database models
│   ├── views.py              # View logic
│   └── urls.py               # URL routing
├── Ewiz_project/             # Project settings
│   ├── settings.py           # Global settings
│   ├── urls.py               # Project-level URL routing
│   └── wsgi.py               # WSGI application
├── manage.py                 # Django's command-line utility
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
├── .env                      # Environment variables
└── .gitignore                # Ignored files in version control
```
