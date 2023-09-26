#!/bin/bash
cd /home/ubuntu/build

sudo npm install
sudo pm2 kill
sudo pm2 start "npm run start:prod"
sudo pm2 start app.js
sudo pm2 startup
sudo pm2 save

# sudo /usr/bin/yarn
# sudo /usr/bin/yarn db:pull //prisma 사용했을 경우만
# sudo /usr/bin/yarn generate //prisma 사용했을 경우만 - 해당명령어는 위의 scripts의 명령어임
# sudo /usr/bin/pm2 start dist