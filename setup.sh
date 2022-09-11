cp /app/.heroku/python/lib/python3.10/site-packages/app/.heroku/python/lib/libyara.so /app/.heroku/python/lib/libyara.so

mkdir -p ~/.streamlit/

echo "\
[general]\n\
email = \"user@domain.com\"\n\
" > ~/.streamlit/credentials.toml

echo "\
[server]\n\
headless = true\n\
enableCORS=false\n\
port = $PORT\n\
maxUploadSize = 10\n\
" > ~/.streamlit/config.toml
