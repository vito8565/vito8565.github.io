-- «Свалка»: схема базы для Supabase.
-- Как применить: Supabase → SQL Editor → New query → вставить весь файл → Run.
-- Файл можно запускать повторно: он ничего не ломает и не дублирует.

-- ================= Ярлыки =================
create table if not exists public.labels (
  id           bigint generated always as identity primary key,
  name         text not null check (char_length(name) between 1 and 40),
  url          text check (url is null or (url ~* '^https://' and char_length(url) <= 300)),
  category     text not null check (category in ('сайт','игра','фильм','видео','реклама')),
  description  text not null default '' check (char_length(description) <= 140),
  size         text not null default 'S' check (size in ('S','M','L','XL')),
  status       text not null default 'pending' check (status in ('pending','approved','rejected')),
  opens        integer not null default 0,
  last_opened  timestamptz,
  created_at   timestamptz not null default now(),
  approved_at  timestamptz,
  submitter    text   -- хэш IP подавшего, только для лимитов; наружу не отдаётся
);
alter table public.labels add column if not exists submitter text;

-- ================= Заявки (вместо оплаты) =================
create table if not exists public.requests (
  id          bigint generated always as identity primary key,
  label_id    bigint references public.labels(id) on delete set null,
  kind        text not null check (kind in ('size','lift','polish','sign','sponsor','report')),
  wanted_size text check (wanted_size in ('M','L','XL')),
  contact     text not null default '' check (char_length(contact) <= 80),
  note        text not null default '' check (char_length(note) <= 300),
  created_at  timestamptz not null default now(),
  submitter   text
);
alter table public.requests add column if not exists submitter text;

-- ================= Защита от спама =================
-- Служебные функции живут в отдельной схеме: Supabase API её наружу не публикует,
-- поэтому вызвать их напрямую через /rest/v1/rpc нельзя.
create schema if not exists svalka_private;
grant usage on schema svalka_private to anon, authenticated;

-- Хэш IP посетителя. Supabase стоит за Cloudflare, поэтому берём cf-connecting-ip.
-- Это базовая защита: спамер с пулом прокси её обойдёт, но общий потолок очереди всё равно удержит базу.
create or replace function svalka_private.client() returns text
language sql stable as $$
  select md5(coalesce(
    nullif(current_setting('request.headers', true), '')::json->>'cf-connecting-ip',
    split_part(nullif(current_setting('request.headers', true), '')::json->>'x-forwarded-for', ',', 1),
    'unknown') || ':svalka');
$$;

-- Счётчики считаются с правами владельца: посетитель сам чужие строки не видит.
create or replace function svalka_private.check_limits(tbl text, who text) returns void
language plpgsql security definer set search_path = public as $$
declare mine int; total int;
begin
  if tbl = 'labels' then
    select count(*) into mine  from labels where submitter = who and created_at > now() - interval '1 day';
    select count(*) into total from labels where status = 'pending';
    if mine  >= 5   then raise exception 'Лимит: не больше 5 ярлыков в сутки'; end if;
    if total >= 300 then raise exception 'Очередь на проверку переполнена, попробуй завтра'; end if;
  else
    select count(*) into mine  from requests where submitter = who and created_at > now() - interval '1 day';
    select count(*) into total from requests where created_at > now() - interval '1 day';
    if mine  >= 10  then raise exception 'Лимит: не больше 10 заявок в сутки'; end if;
    if total >= 500 then raise exception 'Слишком много заявок за сутки, попробуй завтра'; end if;
  end if;
end $$;
revoke all on function svalka_private.client() from public;
revoke all on function svalka_private.check_limits(text, text) from public;
grant execute on function svalka_private.client() to anon, authenticated;
grant execute on function svalka_private.check_limits(text, text) to anon, authenticated;

-- ================= Правила вставки ярлыка =================
-- Посетитель не может сам себе выставить статус, размер или открытия.
-- Ссылки с запрещёнными словами сразу уходят в отклонённые.
create or replace function public.labels_before_insert() returns trigger
language plpgsql as $$
begin
  if current_user in ('anon','authenticated') then
    new.submitter := svalka_private.client();
    perform svalka_private.check_limits('labels', new.submitter);
    new.status := 'pending';
    new.size := 'S';
    new.opens := 0;
    new.last_opened := null;
    new.approved_at := null;
    new.created_at := now();
    if new.category = 'реклама' then new.category := 'сайт'; end if;
    if new.url is null then raise exception 'Нужна ссылка'; end if;
    if lower(new.name || ' ' || new.url || ' ' || new.description)
       ~ '(casino|kazino|казино|1xbet|torrent|торрент|rutracker|porn|xxx|warez|vulkan|займ)' then
      new.status := 'rejected';
    end if;
  end if;
  if new.status = 'approved' and new.approved_at is null then new.approved_at := now(); end if;
  return new;
end $$;

drop trigger if exists labels_before_insert on public.labels;
create trigger labels_before_insert before insert on public.labels
  for each row execute function public.labels_before_insert();

-- Когда ты одобряешь ярлык в таблице, ставится время одобрения.
create or replace function public.labels_before_update() returns trigger
language plpgsql as $$
begin
  if new.status = 'approved' and old.status is distinct from 'approved' then
    new.approved_at := now();
  end if;
  return new;
end $$;

drop trigger if exists labels_before_update on public.labels;
create trigger labels_before_update before update on public.labels
  for each row execute function public.labels_before_update();

create or replace function public.requests_before_insert() returns trigger
language plpgsql as $$
begin
  if current_user in ('anon','authenticated') then
    new.submitter := svalka_private.client();
    perform svalka_private.check_limits('requests', new.submitter);
    new.created_at := now();
  end if;
  return new;
end $$;

drop trigger if exists requests_before_insert on public.requests;
create trigger requests_before_insert before insert on public.requests
  for each row execute function public.requests_before_insert();

-- ================= Права доступа =================
alter table public.labels   enable row level security;
alter table public.requests enable row level security;

-- Снимаем всё, что Supabase раздаёт по умолчанию, и выдаём только нужное.
revoke all on public.labels   from anon, authenticated;
revoke all on public.requests from anon, authenticated;

-- Ярлыки: читать можно только одобренные и только безопасные колонки (без submitter).
grant select (id, name, url, category, description, size, opens, last_opened, approved_at)
  on public.labels to anon, authenticated;
-- Подать можно только содержимое; статус, размер и прочее перезапишет триггер.
grant insert (name, url, category, description) on public.labels to anon, authenticated;

drop policy if exists "все видят одобренное" on public.labels;
create policy "все видят одобренное" on public.labels
  for select to anon, authenticated using (status = 'approved');

drop policy if exists "любой может подать ярлык" on public.labels;
create policy "любой может подать ярлык" on public.labels
  for insert to anon, authenticated with check (true);

-- Заявки: только отправить. Прочитать контакты может лишь владелец в панели Supabase.
grant insert (label_id, kind, wanted_size, contact, note) on public.requests to anon, authenticated;

drop policy if exists "любой может оставить заявку" on public.requests;
create policy "любой может оставить заявку" on public.requests
  for insert to anon, authenticated with check (true);

-- Изменять и удалять посетители не могут ничего: таких прав и политик нет.

-- ================= Счётчик открытий =================
-- Открытие ярлыка: +1, от этого он блестит и всплывает.
-- Один посетитель (IP) засчитывается не чаще раза в час на ярлык, чтобы накрутка была дорогой.
create table if not exists public.label_opens (
  label_id  bigint not null references public.labels(id) on delete cascade,
  who       text   not null,
  opened_at timestamptz not null default now(),
  primary key (label_id, who)
);
alter table public.label_opens enable row level security;
revoke all on public.label_opens from anon, authenticated;

drop function if exists public.open_label(bigint);
create or replace function public.open_label(p_label_id bigint) returns void
language plpgsql security definer set search_path = public as $$
declare v_who text := svalka_private.client(); v_prev timestamptz;
begin
  if not exists (select 1 from labels l where l.id = p_label_id and l.status = 'approved') then return; end if;
  select o.opened_at into v_prev from label_opens o where o.label_id = p_label_id and o.who = v_who;
  if v_prev is not null and v_prev > now() - interval '1 hour' then return; end if;
  insert into label_opens as o (label_id, who, opened_at) values (p_label_id, v_who, now())
    on conflict on constraint label_opens_pkey do update set opened_at = excluded.opened_at;
  update labels l set opens = l.opens + 1, last_opened = now() where l.id = p_label_id;
end $$;
revoke all on function public.open_label(bigint) from public;
grant execute on function public.open_label(bigint) to anon, authenticated;

-- ================= Стартовые ярлыки от редакции =================
insert into public.labels (name, category, description, url, size, status)
select * from (values
 ('Википедия','сайт','Свободная энциклопедия на сотнях языков','https://ru.wikipedia.org','L','approved'),
 ('Internet Archive','сайт','Архив старых сайтов, книг, фильмов и программ','https://archive.org','M','approved'),
 ('Проект Гутенберг','сайт','Десятки тысяч бесплатных книг','https://www.gutenberg.org','M','approved'),
 ('OpenStreetMap','сайт','Открытая карта мира, которую рисуют люди','https://www.openstreetmap.org','S','approved'),
 ('Radio Garden','сайт','Крутишь глобус и слушаешь радио любого города','https://radio.garden','M','approved'),
 ('Windy','сайт','Живая карта ветра и погоды','https://www.windy.com','S','approved'),
 ('neal.fun','сайт','Странные интерактивные игрушки','https://neal.fun','S','approved'),
 ('Stellarium Web','сайт','Звёздное небо прямо в браузере','https://stellarium-web.org','S','approved'),
 ('Arts & Culture','сайт','Музеи мира онлайн','https://artsandculture.google.com','M','approved'),
 ('Khan Academy','сайт','Бесплатные уроки по математике и наукам','https://ru.khanacademy.org','S','approved'),
 ('Desmos','сайт','Графический калькулятор','https://www.desmos.com/calculator','S','approved'),
 ('Excalidraw','сайт','Рисовалка схем от руки','https://excalidraw.com','S','approved'),
 ('Arzamas','сайт','Курсы по истории и культуре','https://arzamas.academy','M','approved'),
 ('NASA','сайт','Космос из первых рук','https://www.nasa.gov','L','approved'),
 ('Lichess','игра','Шахматы без рекламы и подписок','https://lichess.org','M','approved'),
 ('itch.io','игра','Тысячи инди-игр','https://itch.io','L','approved'),
 ('2048','игра','Складывай плитки до 2048','https://play2048.co','S','approved'),
 ('Little Alchemy 2','игра','Смешивай стихии и создавай мир','https://littlealchemy2.com','S','approved'),
 ('A Dark Room','игра','Текстовая игра, которая разрастается','https://adarkroom.doublespeakgames.com','S','approved'),
 ('Quick, Draw!','игра','Рисуешь, нейросеть угадывает','https://quickdraw.withgoogle.com','S','approved'),
 ('Paperclips','игра','Делай скрепки. Очень много скрепок','https://www.decisionproblem.com/paperclips/','S','approved'),
 ('Slither.io','игра','Змейка против всего интернета','https://slither.io','M','approved'),
 ('Метрополис 1927','фильм','Немое кино, общественное достояние','https://archive.org/search?query=metropolis%201927','M','approved'),
 ('Генерал 1926','фильм','Бастер Китон, общественное достояние','https://archive.org/search?query=the%20general%201926%20buster%20keaton','S','approved'),
 ('Кин-дза-дза!','фильм','Легально в онлайн-кинотеатре Мосфильма','https://cinema.mosfilm.ru','L','approved'),
 ('Сталкер','фильм','Тарковский, легально у Мосфильма','https://cinema.mosfilm.ru','M','approved'),
 ('TED','видео','Лекции по 18 минут обо всём','https://www.ted.com','M','approved'),
 ('TED-Ed','видео','Короткие анимированные уроки','https://ed.ted.com','S','approved'),
 ('Ёжик в тумане','видео','Мультфильм Норштейна','https://www.youtube.com/results?search_query=%D1%91%D0%B6%D0%B8%D0%BA%20%D0%B2%20%D1%82%D1%83%D0%BC%D0%B0%D0%BD%D0%B5%20%D1%81%D0%BE%D1%8E%D0%B7%D0%BC%D1%83%D0%BB%D1%8C%D1%82%D1%84%D0%B8%D0%BB%D1%8C%D0%BC','S','approved'),
 ('Kurzgesagt','видео','Наука в мультиках','https://www.youtube.com/results?search_query=kurzgesagt%20%D0%BD%D0%B0%20%D1%80%D1%83%D1%81%D1%81%D0%BA%D0%BE%D0%BC','M','approved')
) as v(name, category, description, url, size, status)
where not exists (select 1 from public.labels);
