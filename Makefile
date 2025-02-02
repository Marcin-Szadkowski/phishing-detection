PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.49.1-noble

.PHONY reformat:
reformat:
	black src tests
	isort src tests


.PHONY lint:
lint:
	black src tests --diff
	isort src tests --diff
	flake8 src tests


.PHONY start-playwright:
start-playwright:
	docker run -p 3000:3000 --rm --ipc=host --init -it \
 	--workdir /home/pwuser --user pwuser \
 	 --security-opt seccomp=seccomp_profile.json \
 	 -e DISPLAY=host.docker.internal:0 \
 	 -v /tmp/.X11-unix:/tmp/.X11-unix \
 	 $(PLAYWRIGHT_IMAGE) /bin/sh -c "npx -y playwright@1.49.1 run-server --port 3000 --host 0.0.0.0"
