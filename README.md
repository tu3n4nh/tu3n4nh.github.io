# tu3n4nh.github.io

Blog cá nhân — web security, CTF writeups. Dựng bằng Jekyll, GitHub Pages build sẵn.

## Viết bài mới

Tạo file `_posts/YYYY-MM-DD-ten-bai.md`:

```markdown
---
title: "Tên bài"
date: 2024-05-01
description: Một câu mô tả ngắn, dùng cho danh sách bài và meta description.
tags: [writeup, web, xss]
---

Nội dung viết bằng Markdown từ đây.
```

Ảnh để trong `img/posts/<ten-bai>/` và chèn bằng `![mô tả](/img/posts/<ten-bai>/anh.png)`.

Front matter là bắt buộc — `title`, `date`, `description`, `tags`. Không cần sửa `index.html`,
danh sách bài và sidebar tự lấy từ `site.posts`.

## Cấu trúc

```
_config.yml                cấu hình Jekyll
_layouts/default.html      khung trang (topbar, sidebar, footer)
_layouts/post.html         layout bài viết + mục lục tự sinh
_layouts/page.html         layout trang tĩnh
_includes/                 head, topbar, profile, footer
_posts/*.md                bài viết
index.html about.html 404.html
assets/css/style.css       toàn bộ style
```

URL bài viết là `/posts/<ten-file-khong-ngay>.html`.

## Build thử ở máy

```
docker run --rm -v "$PWD":/srv/jekyll -w /srv/jekyll jekyll/jekyll:4 jekyll serve
```
