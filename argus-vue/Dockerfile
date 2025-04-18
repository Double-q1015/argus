# 使用官方 nginx 镜像作为基础镜像
FROM nginx:alpine

# 将构建产物复制到 nginx 的默认静态文件目录
COPY dist/ /usr/share/nginx/html/

# 复制自定义的 nginx 配置文件
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 暴露 80 端口
EXPOSE 80

# 启动 nginx
CMD ["nginx", "-g", "daemon off;"] 