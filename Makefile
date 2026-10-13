.PHONY: help install test lint run run-docker clean

help:
	@echo "Available commands:"
	@echo "  make install     Install dependencies"
	@echo "  make test        Run unit & integration tests"
	@echo "  make run         Run IDPS API Gateway locally"
	@echo "  make run-docker  Start all services using Docker Compose"
	@echo "  make clean       Clean temporary files and cache"

install:
	pip install -e .

test:
	pytest tests/ -v

run:
	uvicorn services.api.main:app --reload --host 0.0.0.0 --port 8080

run-docker:
	docker-compose up --build -d

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
