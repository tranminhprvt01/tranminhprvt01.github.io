export const SITE = {
  website: "https://tranminhprvt01.github.io/", // replace this with your deployed domain
  author: "tranminhprvt01",
  profile: "https://github.com/tranminhprvt01",
  desc: "A blog about CTF writeups and security research",
  title: "Home",
  ogImage: "astropaper-og.jpg",
  lightAndDarkMode: true,
  postPerIndex: 4,
  postPerPage: 4,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
  showArchives: true,
  showBackButton: true, // show back button in post detail
  editPost: {
    enabled: true,
    text: "Suggest changes",
    url: "https://github.com/tranminhprvt01/tranminhprvt01.github.io/edit/main/",
  },
  dynamicOgImage: true,
  dir: "ltr", // "rtl" | "auto"
  lang: "en", // html lang code. Set this empty and default will be "en"
  timezone: "Asia/Ho_Chi_Minh", // Default global timezone (IANA format) https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
} as const;
