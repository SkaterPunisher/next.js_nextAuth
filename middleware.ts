import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { i18n } from './locales/i18n-config';
import { match as matchLocale } from '@formatjs/intl-localematcher';
import Negotiator from 'negotiator';
// import withAuth from 'next-auth/middleware';
import { encode, getToken } from 'next-auth/jwt';
import jwt from 'jsonwebtoken';
// import { authConfig } from './config/auth';
import { DecodedToken, SessionToken } from './types/next-auth';
import { cookies } from 'next/headers';

export const SIGNIN_SUB_URL = '/api/auth/signin';
export const SESSION_TIMEOUT = 60 * 60 * 24 * 28; // 28 day
export const TOKEN_REFRESH_BUFFER_SECONDS = 300;
export const SESSION_SECURE = process.env.NEXTAUTH_URL?.startsWith('https://');
export const SESSION_COOKIE = 'next-auth.session-token';

function getLocale(request: NextRequest): string {
  // Negotiator expects plain object so we need to transform headers
  const negotiatorHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => (negotiatorHeaders[key] = value));

  // @ts-ignore locales are readonly
  const locales: string[] = i18n.locales;

  // Use negotiator and intl-localematcher to get best locale
  let languages = new Negotiator({ headers: negotiatorHeaders }).languages(
    locales,
  );

  const locale = matchLocale(languages, locales, i18n.defaultLocale);

  return locale;
}

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Ignore requests for static files (images, fonts, etc.)
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/api/') ||
    pathname.match(
      /\.(ico|png|jpg|jpeg|svg|gif|webp|mp3|mp4|wav|ogg|avi|pdf|doc|docx|ppt|pptx|xls|xlsx|txt|woff|woff2|eot|ttf|otf)$/,
    )
  ) {
    return;
  }

  const searchParams = request.nextUrl.search;
  let response = NextResponse.next();

  //Получаем session из nextAuth
  const sessionNextAuth = await getToken({ req: request });

  let tokenUpdate = null;
  let refreshUpdate = null;

  if (!sessionNextAuth) {
    response.cookies.delete('access_token');
    response.cookies.delete('refreshToken');
  }

  //Выбираем страницы, где не нужно делать проверку на session
  const isLogoutPage =
    request.nextUrl.pathname.startsWith('/ru/logout') ||
    request.nextUrl.pathname.startsWith('/en/logout') ||
    request.nextUrl.pathname.startsWith('/logout');

  //Если у нас есть session, проверяем её
  if (
    sessionNextAuth &&
    sessionNextAuth.error !== 'ErrorRefresh' &&
    !isLogoutPage &&
    shouldUpdateToken(sessionNextAuth as SessionToken)
  ) {
    const accessTokenOnCookie = cookies().get('access_token')?.value;
    const refreshTokenOnCookies = cookies().get('refreshToken')?.value;

    if (
      accessTokenOnCookie &&
      refreshTokenOnCookies &&
      sessionNextAuth.refreshToken !== refreshTokenOnCookies &&
      sessionNextAuth.accessToken !== accessTokenOnCookie
    ) {
      console.log(
        'Проверка middleware. Токены обновились через baseQueryWithRefreshToken, обновим данные и в сессии через middleware',
      );

      //Декодируем полученный токен
      const decoded = decodeTokenMiddleware(
        accessTokenOnCookie,
      ) as DecodedToken;

      sessionNextAuth.refreshToken = refreshTokenOnCookies;
      sessionNextAuth.accessToken = accessTokenOnCookie;
      sessionNextAuth.decoded = decoded;

      //Обновляем данные user
      const newUserData = await getUserMiddleware(
        sessionNextAuth as SessionToken,
      );

      console.log(
        'Новыйе данные после baseQueryWithRefreshToken из middleware',
        newUserData,
      );

      tokenUpdate = newUserData.accessToken;
      refreshUpdate = newUserData.refreshToken;

      //Делаем новую session для nextAuth
      const newSessionToken = await encode({
        secret: process.env.NEXTAUTH_SECRET!,
        token: newUserData,
        maxAge: SESSION_TIMEOUT,
      });

      //Обновляем полученную сессию в nextAuth
      response = updateCookie(newSessionToken, request, response);
    } else {
      console.log(
        'AccessToken умер - нужно обновить, старый токен в middleware -> ',
        sessionNextAuth,
      );

      //Получаем новый token из refreshToken
      const newTokenData = await refreshAccessTokenMiddleware(
        sessionNextAuth as SessionToken,
      );

      //Обновляем данные user
      const newUserData = await getUserMiddleware(newTokenData);

      console.log('Новый токен из middleware', newUserData);

      tokenUpdate = newUserData.accessToken;
      refreshUpdate = newUserData.refreshToken;

      //Делаем новую session для nextAuth
      const newSessionToken = await encode({
        secret: process.env.NEXTAUTH_SECRET!,
        token: newUserData,
        maxAge: SESSION_TIMEOUT,
      });

      //Обновляем полученную сессию в nextAuth
      response = updateCookie(newSessionToken, request, response);
    }
  }

  // Проверяем есть ли какая нибудь locale в pathname
  const pathnameIsMissingLocale = i18n.locales.every(
    (locale) =>
      !pathname.startsWith(`/${locale}/`) && pathname !== `/${locale}`,
  );

  // Делаем редирект если нет locale
  if (pathnameIsMissingLocale) {
    const locale = getLocale(request);

    const url = new URL(
      `/${locale}${
        pathname.startsWith('/') ? '' : '/'
      }${pathname}${searchParams}`,
      request.url,
    );

    const newResponse = NextResponse.redirect(url);
    newResponse.cookies.set('locale', locale);

    if (tokenUpdate && refreshUpdate) {
      newResponse.cookies.set('access_token', tokenUpdate);
      newResponse.cookies.set('refreshToken', refreshUpdate);
    }

    response.cookies.getAll().forEach((cookie) => {
      newResponse.cookies.set(cookie.name, cookie.value);
    });

    return newResponse;
  } else {
    response.cookies.set('locale', pathname.split('/')[1]);

    if (tokenUpdate && refreshUpdate) {
      response.cookies.set('access_token', tokenUpdate);
      response.cookies.set('refreshToken', refreshUpdate);
    }

    return response;
  }
}

export const config = {
  // Matcher ignoring `/_next/` and `/api/, '/public`
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico|public).*)'],
};

export function shouldUpdateToken(token: SessionToken): boolean {
  if (token.decoded && token.decoded.exp < Date.now() / 1000 + 1) return true; // берем 1 сек. буффером
  return false;
}

export function updateCookie(
  sessionToken: string | null,
  request: NextRequest,
  response: NextResponse,
): NextResponse<unknown> {
  /*
   * 1. Установить cookies запроса для входещейго getServerSession для чтения новой сессии
   * 2. Обновленные cookies запроса могут быть переданы на сервер только в том случае, если они были переданы тут после обновлений
   * 3. Устанавливаем cookies ответа для отправки обратно в браузер
   */

  if (sessionToken) {
    // Set the session token in the request and response cookies for a valid session
    request.cookies.set(SESSION_COOKIE, sessionToken);
    response = NextResponse.next({
      request: {
        headers: request.headers,
      },
    });
    response.cookies.set(SESSION_COOKIE, sessionToken, {
      httpOnly: true,
      maxAge: SESSION_TIMEOUT,
      secure: SESSION_SECURE,
    });
  }
  return response;
}

export async function refreshAccessTokenMiddleware(token: SessionToken) {
  try {
    const refreshResponse = await fetch(
      `${process.env.BASE_URL}/auth/refresh`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${token.accessToken}`,
          Cookie: `refreshToken=${token.refreshToken};`,
        },
        credentials: 'include',
      },
    );

    const newTokens = await refreshResponse.json();

    if (newTokens.statusCode == 401) {
      console.log(
        'Ошибка получения RefreshToken в middleware',
        newTokens.message,
      );
      return { ...token, error: 'ErrorRefresh' };
    } else {
      //Получаем cookies из headers
      const headers = new Headers(refreshResponse.headers);
      const cookies = headers.getSetCookie();

      //Декодируем полученный токен
      const decoded = decodeTokenMiddleware(
        newTokens!.accessToken,
      ) as DecodedToken;

      return {
        ...token,
        accessToken: newTokens.accessToken,
        refreshToken: cookies[0].match(/refreshToken=([^;]*)/)?.[1]!,
        decoded,
      };
    }
  } catch (error) {
    console.log('Ошибка получения RefreshToken в middleware', error);
    return { ...token, error: 'ErrorRefresh' };
  }
}

// Функция для декодирования токена
export function decodeTokenMiddleware(accessToken: string) {
  return jwt.decode(accessToken);
}

export async function getUserMiddleware(token: SessionToken) {
  try {
    const refreshUserResponse = await fetch(`${process.env.BASE_URL}/user`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${token.accessToken}`,
        Cookie: `refreshToken=${token.refreshToken};`,
      },
      credentials: 'include',
    });

    const newUser = await refreshUserResponse.json();

    if (newUser.statusCode == 401) {
      console.log(
        'Ошибка получения пользователя при refreshTokenMiddleware:',
        newUser.message,
      );
      return { ...token, error: 'ErrorRefresh' };
    } else {
      return {
        ...token,
        user: newUser,
      };
    }
  } catch (error) {
    console.log(
      'Ошибка получения пользователя при refreshTokenMiddleware:',
      error,
    );
    return { ...token, error: 'ErrorRefresh' };
  }
}
