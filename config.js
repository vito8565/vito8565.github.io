// Настройки подключения к базе Supabase.
// Пока поля пустые, сайт работает в демо-режиме: куча из стартовых ярлыков, приём заявок выключен.
// Где взять значения: Supabase → Project Settings → API (или Data API / API Keys).
//   supabaseUrl — Project URL, вида https://xxxx.supabase.co
//   supabaseKey — publishable key (sb_publishable_...) или старый anon public key (eyJ...)
// Эти ключи публичные по задумке: доступ ограничивают правила в supabase.sql.
// НИКОГДА не вставляй сюда secret / service_role key.
window.SVALKA_CONFIG = {
  supabaseUrl: '',
  supabaseKey: ''
};
