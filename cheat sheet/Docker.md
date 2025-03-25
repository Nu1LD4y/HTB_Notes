# 1. Image
```python
# 查看本機
image docker images busybox

# 下載 image 
docker pull busybox

# remove image
docker rmi hello-world

# commit new image
# Terminal 1 
docker run --rm -it --name some busybox
# 進去建立一些檔案 
echo new commit > file cat file 
# Terminal 2，commit 檔案系統成為新的 image 
docker commit some myimage 
# 執行新的 image 
docker run --rm -it --name new myimage 
# 檢查剛剛建立的檔案是否存在
cat file

#官方建議
# Dockerfile

## =======  dockerfile ==========
FROM alpine

RUN apk add --no-cache vim
## =========================

# Build 一個新的 image，完成後 tag 為 vim 
docker build -t vim . 

# 使用新的 image 執行 container 
docker run --rm -it --name new vim

```

# 2. Container
## - 基本操作
```python
# 建立 container 
docker create -i -t --name foo busybox 

# 使用 docker ps 確認 container 狀態 
docker ps -a

# 執行 container，`foo` 是前一節創建 container 指定的名字。 docker start -i foo

# 使用 docker ps 可以觀察到狀態是 `Up`，正常運行中。 
docker ps -a

docker stop foo

docker rm foo

docker rm -f foo

# 加帶 --rm 參數自動把這個 container 移除
docker run --rm --name web httpd

# 執行完會馬上回到 host 上 
docker run -d httpd 

# 觀察 container 是否在運作中
docker ps

# 使用 exec 進入 container
docker exec -it web bash
```

## - Networking
```python
# 加上 -p 參數
docker run -d -p 8080:80 httpd 

# 確認 port 有被開出來了 
curl http://localhost:8080/


# 執行 container 
docker run -d -it -v `pwd`:/usr/local/apache2/htdocs -p 8080:80 httpd 

# 測試對應路徑
curl http://localhost:8080/test.html

# 看 log
# 加 -f 選項後，container log 只要有更新，畫面就會更新
docker logs -f web

# wget 
docker run --rm busybox wget -q -O - http://web/ 

# 比較沒加 link 與有加 link 的差別 
docker run --rm --link web busybox wget -q -O - http://web/

# 使用別名 
docker run --rm --link web:alias busybox wget -q -O - http://alias/

# 官方建議
## 使用 Network

# 建立 network 
docker network create my-net 
# Terminal 1 啟動 Apache
docker run --rm --name web -p 8080:80 --network my-net httpd 
# Terminal 2 透過 BusyBox 連結 Apache 
docker run --rm --network my-net busybox wget -q -O - web
```

## - Environment
```python
# 查看原本的 env 
docker run --rm busybox env 

# 給 env 設定後再看 env 的內容 
docker run --rm -e DB_HOST=mysql busybox env
```

# 3. Docker Compose
