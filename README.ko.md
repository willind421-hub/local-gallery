# Local Gallery

로컬 폴더에 쌓인 생성 결과물(이미지, 영상, 오디오, HTML 보고서)을 브라우저로 보여 주는
읽기 전용 웹 갤러리입니다. 원본 파일은 버튼 한 번으로 내려받을 수 있습니다.
파이썬 표준 라이브러리만 쓰는 단일 모듈이며 의존성이 없습니다.

[English](README.md) · [日本語](README.ja.md)

## 해결하려는 문제

스크립트, 렌더러, AI 에이전트는 결과물을 계속 출력 폴더에 씁니다. 이것을 브라우저에서
썸네일 그리드, 영상 바로 재생, 원본 다운로드 버튼으로 보고 싶지만, 미디어 서버를 따로
설치하고 싶지는 않습니다. 그렇다고 뷰어가 파일을 바꾸거나 지우거나 폴더 밖을 돌아다닐
수 있어서도 안 됩니다.

Local Gallery는 두 역할을 나눕니다. 파일을 만드는 쪽은 쓰기만 하고, 갤러리는 읽어서
보여 주기만 합니다.

## 보장하는 것

- **읽기 전용.** `GET`만 구현합니다. `POST`/`PUT`/`DELETE`는 `405`, 그 밖의 메서드는
  `501`로 응답합니다. 파일을 쓰거나 이름을 바꾸거나 지우는 코드가 아예 없습니다.
  원본 다운로드는 "읽기"이므로 지원합니다.
- **등록한 루트 밖으로 나가지 않음.** `..` 조각, 드라이브 문자를 비롯한 `:` 포함 조각
  (NTFS 대체 데이터 스트림 포함), 절대 경로, 퍼센트 인코딩된 상위 이동, 루트 밖을
  가리키는 심볼릭 링크·정션을 모두 거부합니다. 포함 여부는 완전히 해석한(resolve)
  경로로 검사합니다.
- **숨김·비밀로 보이는 항목은 보이지 않음.** 점(.)으로 시작하는 파일과 자격 증명처럼
  보이는 이름(`.env`, `*.pem`, `*.key`, `id_rsa`, `token`·`secret`·`password`·
  `credential`이 들어간 이름, `.ssh`·`.aws` 같은 폴더 등)은 목록에서 빠지고 직접
  요청해도 받을 수 없습니다. Windows 8.3 짧은 이름(`ENV~1`)이나 루트 안의 평범한
  이름을 단 심볼릭 링크 같은 별칭으로도 우회할 수 없습니다.
- **능동 콘텐츠가 갤러리 출처에서 실행되지 않음.** SVG, HTML, XML은 항상 첨부 파일로
  보내고 `Content-Security-Policy: default-src 'none'; sandbox`를 붙입니다. 모든 파일
  응답에 `X-Content-Type-Options: nosniff`가 붙습니다.
- **어떤 파일 이름이든 다운로드 가능.** `Content-Disposition`은 RFC 6266 / RFC 5987을
  따릅니다. ASCII 대체 이름과 함께 `filename*`에 UTF-8 원래 이름을 실어 보내므로 한국어,
  일본어, 이모지 이름도 그대로 저장되고, 이름 속 따옴표나 줄바꿈(CR/LF)으로 헤더를
  끼워 넣을 수 없습니다.
- **기본은 로컬 전용.** 따로 지정하지 않으면 `127.0.0.1`에만 바인딩합니다.
- **선택적 접근 토큰**과 HttpOnly 세션 쿠키(아래 참고).

## 설계

모듈 하나(`local_gallery/gallery.py`)로 되어 있습니다. 판단은 모두 순수 함수가 맡고,
얇은 `http.server` 핸들러가 이를 호출합니다.

| 함수 | 역할 |
| --- | --- |
| `parse_roots(spec, default_root, default_name)` | `이름=경로;이름=경로` → `{이름: 해석된 폴더}`, 없으면 기본 폴더 하나 |
| `is_hidden(name)` | 점 파일, 비밀로 보이는 이름, 보호 폴더 판정 |
| `safe_resolve(roots, rel)` | `루트/하위/경로` → `(루트, 절대 경로)` 또는 `None` |
| `list_dir(path)` | 숨김 항목을 뺀 폴더 목록(폴더 먼저, 최대 2000개) |
| `classify_ext(name)` | 렌더링용 종류 `image` / `video` / `audio` / `other` |
| `content_disposition(filename)` | RFC 5987 첨부 헤더 값 |
| `render_roots_page`, `render_dir_page` | HTML 페이지(이름은 모두 이스케이프, 링크는 모두 퍼센트 인코딩) |
| `serve(roots, host=, port=, token=)` | Ctrl+C까지 서버 실행 |
| `main(argv)` | `local-gallery` 명령 |

`safe_resolve`는 다음 순서로 검사합니다. 모르는 루트 이름 → `..`·`.`·`:` 조각 → 숨김
조각 → `Path.resolve()` 결과가 루트 안에 있는지 → 해석된 경로에 숨김 이름이 없는지.
순수 함수이므로 테스트에서 직접 호출하고, HTTP로도 한 번 더 확인합니다.

썸네일은 브라우저가 원본을 줄여서 보여 주는 방식(`<img loading="lazy">`)입니다. 서버
쪽 썸네일 캐시나 트랜스코딩은 없습니다. 파일은 64 KiB 단위로 스트리밍합니다.

**토큰 흐름.** `LOCAL_GALLERY_TOKEN`을 설정하면 첫 요청에 `?token=<값>`이 있어야 합니다.
응답이 `HttpOnly; SameSite=Strict` 쿠키를 심기 때문에 이후 갤러리 안의 링크는 URL에
토큰 없이 동작합니다. 맞는 토큰도 쿠키도 없는 요청은 `401`입니다. 비교는 상수 시간으로
합니다.

## 빠른 시작

```bash
pip install .                 # 개발용: pip install -e ".[test]"

cd path/to/outputs
local-gallery                 # 현재 폴더를 http://127.0.0.1:18140 에서 보여 줌

# 여러 폴더, 이름 지정, 다른 포트
local-gallery --root renders=./renders --root /srv/reports --port 8080

python -m local_gallery --help
```

출력된 주소를 열면 폴더 카드가 나오고, 들어가면 이미지 썸네일, 영상·오디오 플레이어,
원본을 내려받는 ⬇ 버튼이 있는 그리드가 보입니다.

| 설정 | CLI | 환경 변수 | 기본값 |
| --- | --- | --- | --- |
| 폴더 | `--root [이름=]경로` (반복 가능) | `LOCAL_GALLERY_ROOTS="이름=경로;이름=경로"` | 현재 폴더 |
| 바인딩 주소 | `--host` | `LOCAL_GALLERY_HOST` | `127.0.0.1` |
| 포트 | `--port` | `LOCAL_GALLERY_PORT` | `18140` |
| 접근 토큰 | — | `LOCAL_GALLERY_TOKEN` | 없음(localhost에서 공개) |

`--root`가 `LOCAL_GALLERY_ROOTS`보다 우선합니다. `이름=` 없이 준 루트는 폴더 이름을
그대로 이름으로 쓰고, 이름이 겹치면 실행을 거부합니다.

### 접근 토큰

토큰은 환경 변수로만 받습니다. 셸 기록이나 프로세스 목록에 남지 않게 하기 위해서입니다.
URL에 안전한 무작위 ASCII 값을 쓰세요.

```bash
export LOCAL_GALLERY_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
local-gallery
# http://127.0.0.1:18140/?token=<같은 값> 을 한 번 열면 이후에는 쿠키로 유지됨
```

PowerShell: `$env:LOCAL_GALLERY_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(24))"`

기본으로 들어 있거나 자동 생성되는 토큰은 없습니다. 토큰은 2차 방어선일 뿐 네트워크
접근 제어를 대신하지 않습니다. TLS가 없고, 첫 URL에는 토큰이 한 번 들어갑니다.

### HTTP 엔드포인트

| 요청 | 결과 |
| --- | --- |
| `GET /` | 루트마다 카드 하나 |
| `GET /view?path=루트/하위/폴더` | 폴더 그리드 |
| `GET /raw?path=루트/하위/파일` | 파일(미디어는 인라인, SVG/HTML/XML은 첨부) |
| `GET /raw?path=루트/하위/파일&download=1` | 첨부 파일로 다운로드 |

거부 코드: `401` 토큰 필요, `403` 경로 규칙 위반, `404` 없음, `405` 쓰기 메서드.

## 테스트 실행

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest -q
```

일부 테스트는 운영체제가 준비 조건을 제공하지 못하면 건너뜁니다. 심볼릭 링크(개발자
모드나 관리자 권한이 없는 Windows — 폴더 링크 테스트는 이때 NTFS 정션으로 대신 검사)와
Windows 8.3 짧은 이름(볼륨에서 켜져 있을 때만)이 해당합니다.

### 예제

```bash
python examples/demo.py          # 합성 폴더 + 실제 서버, 응답 결과를 출력
python examples/demo.py --keep   # 같은 과정 뒤 서버를 계속 띄워 두어 직접 둘러볼 수 있음
```

데모는 임시 폴더에 PNG 그라데이션, 한국어 이름의 HTML 보고서, 메모, 숨김 `.env`를 만든
뒤 폴더 목록, RFC 5987 다운로드 헤더, 거부되는 요청(`../`, `%2e%2e`, `.env`, `POST`)을
보여 줍니다.

## 한계와 하지 않는 것

- 업로드, 삭제, 이름 변경, 편집은 없습니다. 의도한 설계입니다.
- TLS와 사용자 계정이 없습니다. `127.0.0.1`에 두고, 원격 접속이 필요하면 공개 인터페이스에
  직접 바인딩하지 말고 VPN이나 인증이 있는 리버스 프록시를 쓰세요.
- 토큰은 하나의 공유 값이며 쿠키에 그대로 저장됩니다.
- 서버 쪽 썸네일, 트랜스코딩, 페이지 나누기가 없습니다. 큰 이미지가 많은 폴더는
  브라우저에 무겁고, 목록은 폴더당 2000개에서 멈춥니다.
- `HEAD`와 HTTP `Range`를 지원하지 않아 긴 영상의 탐색이 제한되거나 일부 브라우저가
  영상 스트리밍을 거부할 수 있습니다.
- 숨김 필터는 내용이 아니라 이름으로 판단합니다. 평범한 이름의 비밀 파일이 있는 폴더를
  루트로 지정하지 마세요.
- 루트 밖을 가리키는 심볼릭 링크가 목록에 (대상 크기와 함께) 보일 수 있지만, 열면
  거부됩니다.

## 출처

Local Gallery는 개인 AI 비서 프로젝트 willind의 일부로 처음 만들어졌고, 비서가 만든
이미지·영상·보고서를 보여 주는 데 쓰였습니다. 이 저장소는 그 기능을 독립적으로 떼어 낸
것으로, 프로젝트 전용 경로와 이름을 옵션으로 바꾸고 테스트를 합성 데이터로 옮겼습니다.

## 라이선스

Apache License 2.0 — [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 보세요.
