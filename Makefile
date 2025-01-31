
.PHONY reformat:
reformat:
	black src tests
	isort src tests


.PHONY lint:
lint:
	black src tests --diff
	isort src tests --diff
	flake8 src tests
