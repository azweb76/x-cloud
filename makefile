init:
	pip install -r requirements.txt

test:
	py.test tests

docker_build:
	docker build -t azweb76/xcloud:0.0.1 .
	docker tag azweb76/xcloud:0.0.1 azweb76/xcloud:latest

docker_publish:
	docker push azweb76/xcloud:0.0.1
	docker push azweb76/xcloud:latest

.PHONY: init test
