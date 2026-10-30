# tu3n4nh.github.io

Blog cá nhân — web security, CTF writeups.

Trang tĩnh thuần HTML/CSS, không build step. Nền là `img/bg.gif`, giữ lại từ bản `my-blog` cũ.

## Cấu trúc

```
index.html               trang chủ + danh sách bài
posts/*.html             từng bài viết
about.html               404.html
assets/css/style.css     toàn bộ style
img/bg.gif img/avatar.jpg
```

## Thêm bài mới

1. Copy một file trong `posts/` thành `posts/ten-bai.html`.
2. Viết nội dung, sửa `<title>`, `.eyebrow`, `.meta`, mục lục trong `rail-list`.
3. Thêm một `<li>` vào `.post-list` trong `index.html` và một dòng vào `rail-list` ở sidebar.
