FROM node:18-alpine

RUN apk update \
	&& apk upgrade \
	&& apk add --no-cache \
		chromium \
		python3 \
		make

COPY . /app

WORKDIR /app

RUN yarn remove bcrypto
RUN yarn
RUN yarn build

# copy outputs to mounted volume
CMD ["cp", "-r", "/app/build", "/build"]
