import { type AuthOptions } from 'next-auth';
import jwt from 'jsonwebtoken';
import CredentialsProvider from 'next-auth/providers/credentials';
import axios from './axios';
import {
  AdministratorUser,
  ModeratorUser,
  SpecialistUser,
  User,
} from '../types/user/User';
import { DecodedToken, SessionToken } from '@/types/next-auth';
import { cookies } from 'next/headers';

export const authConfig: AuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        username: { label: 'email', type: 'text' },
        password: { label: 'password', type: 'password' },
      },

      // @ts-ignore
      async authorize(credentials, req) {
        // Берем данные из формы входа
        const email = credentials?.username;
        const password = credentials?.password;

        //Проверяем есть ли email и password
        if (!email || !password) {
          return null;
        } else {
          //Делаем запрос на получение токена (если есть email и password)
          const resData = await signIn(email, password);

          //Декодируем полученный токен
          const decoded = decodeToken(resData!.accessToken) as DecodedToken;

          //Делаем запрос на получение пользователя, если получили token
          const userData = await getUser(
            resData!.accessToken,
            resData!.cookies!,
          );

          cookies().set('access_token', resData!.accessToken);
          cookies().set(
            'refreshToken',
            resData?.cookies![0].match(/refreshToken=([^;]*)/)?.[1]!,
          );

          return {
            accessToken: resData!.accessToken,
            decoded,
            refreshToken:
              resData?.cookies![0].match(/refreshToken=([^;]*)/)?.[1]!,
            user: userData,
          };
        }
      },
    }),
  ],

  session: {
    strategy: 'jwt',
  },

  callbacks: {
    async jwt({ token, user, session, trigger }: any) {
      // Проверяем есть ли уже ошибка, чтобы не выполнять несколько раз
      if (token.error === 'ErrorRefresh') {
        return { ...token, ...user };
      }

      // Проверяем есть ли токен и не просрочен ли он
      if (token.decoded && token.decoded.exp < Date.now() / 1000) {
        const accessTokenOnCookie = cookies().get('access_token')?.value;
        const refreshTokenOnCookies = cookies().get('refreshToken')?.value;

        if (
          accessTokenOnCookie &&
          refreshTokenOnCookies &&
          token.refreshToken !== refreshTokenOnCookies &&
          token.accessToken !== accessTokenOnCookie
        ) {
          console.log(
            'Проверка callbacks jwt. Токены обновились через baseQueryWithRefreshToken, обновим данные и в сессии',
          );

          //Декодируем полученный токен
          const decoded = decodeToken(accessTokenOnCookie) as DecodedToken;

          //Делаем запрос на получение пользователя при refreshToken
          const newUserData = await getUserRefresh(
            token,
            refreshTokenOnCookies,
            accessTokenOnCookie,
          );

          if (newUserData.error === 'ErrorRefresh') {
            return { ...token, error: 'ErrorRefresh' };
          }

          console.log('accessTokenOnCookie', accessTokenOnCookie);
          console.log('accessTokenOnSession', token.accessToken);
          console.log('refreshTokenOnCookies', refreshTokenOnCookies);
          console.log('refreshTokenOnSession', token.refreshToken);

          console.log(
            'Успешно обновили accessToken и refreshToken, когда accessToken и refreshToken обновились через baseQueryWithRefreshToken',
          );
          return {
            accessToken: accessTokenOnCookie,
            decoded,
            refreshToken: refreshTokenOnCookies,
            user: newUserData,
            error: newUserData.error ? newUserData.error : null,
          };
        } else {
          // берем 1 сек. буффером
          console.log(
            'Token сдох callbaks jwt. Пытаемся получить refreshToken. Старый токен -> ',
            token.accessToken,
          );

          //Делаем запрос за refreshToken
          const newTokenData = await refreshAccessToken(token);
          if (newTokenData.error === 'ErrorRefresh') {
            return { ...token, error: 'ErrorRefresh' };
          }

          //Декодируем полученный токен
          const decoded = decodeToken(
            newTokenData.newAccessToken.accessToken,
          ) as DecodedToken;

          //Делаем запрос на получение пользователя при refreshToken
          const newUserData = await getUserRefresh(
            token,
            newTokenData.newRefreshToken!,
            newTokenData.newAccessToken.accessToken,
          );

          if (newUserData.error === 'ErrorRefresh') {
            return { ...token, error: 'ErrorRefresh' };
          }

          console.log(
            'Успешно обновили accessToken и refreshToken, когда accessToken сдох',
          );
          cookies().set(
            'access_token',
            newTokenData.newAccessToken.accessToken,
          );
          cookies().set('refreshToken', newTokenData.newRefreshToken!);
          return {
            accessToken: newTokenData!.newAccessToken.accessToken,
            decoded,
            refreshToken: newTokenData!.newRefreshToken!,
            user: newUserData,
            error: newUserData.error ? newUserData.error : null,
          };
        }
      } else {
        console.log('Токен не просрочен');

        if (trigger === 'update') {
          console.log('sessionUpdate from client', session);
          return { ...session };
        }

        return { ...token, ...user };
      }
    },

    async session({ session, token }: any) {
      if (token) {
        const { error, accessToken, user, refreshToken } = token;
        session.accessToken = accessToken;
        session.refreshToken = refreshToken;

        session.user = user as
          | AdministratorUser
          | SpecialistUser
          | ModeratorUser
          | User;

        if (error) {
          session.error = error;
        }

        return session;
      }

      return session;
    },
  },

  events: {
    // signOut: async ({ session, token }) => doFinalSignoutHandshake(token),
  },

  pages: {
    signIn: '/signin',
    error: '/signin',
    signOut: '/logout',
  },
};

// Функция для получения токена
export async function signIn(email: string, password: string) {
  try {
    const response = await axios.post('/auth/signin', { email, password });

    console.log('Успешная авторизация');
    return {
      accessToken: response.data.accessToken,
      cookies: response.headers['set-cookie'],
    };
  } catch (error: any) {
    console.log('Ошибка авторизации');
    console.log(error);
    throw new Error(error.response.data.message);
  }
}

// Функция для получения пользователя при авторизации
export async function getUser(accessToken: string, cookies: string[]) {
  try {
    const userResponse = await axios.get('/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Cookie: cookies,
      },
    });
    console.log('Пользователь при авторизации получен успешно');

    return userResponse.data as
      | AdministratorUser
      | SpecialistUser
      | ModeratorUser
      | User;
  } catch (error: any) {
    console.log('Ошибка получения пользователя при авторизации не получен');
    throw new Error(error.response.data.message);
  }
}

// Функция для refreshToken
export async function refreshAccessToken(token: SessionToken) {
  try {
    const refreshResponse = await axios.post(
      '/auth/refresh',
      {},
      {
        headers: {
          Authorization: `Bearer ${token.accessToken}`,
          Cookie: `refreshToken=${token.refreshToken};`,
        },
      },
    );

    console.log('RefreshToken получен успешно');
    return {
      ...token,
      newAccessToken: refreshResponse.data,
      newRefreshToken:
        refreshResponse.headers['set-cookie']![0].match(
          /refreshToken=([^;]*)/,
        )?.[1]!,
    };
  } catch (error) {
    console.log('Ошибка получения RefreshToken', error);
    return { ...token, error: 'ErrorRefresh' };
  }
}

// Функция для получения пользователя при запросе на refreshToken
export async function getUserRefresh(
  token: any,
  cookies: string,
  accessToken: string,
) {
  try {
    const userResponse = await axios.get('/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Cookie: `refreshToken=${cookies};`,
      },
    });
    console.log('Пользователь при запросе на refreshToken получен успешно');

    return userResponse.data as
      | AdministratorUser
      | SpecialistUser
      | ModeratorUser
      | User;
  } catch (error) {
    console.log('Ошибка получения пользователя при RefreshToken', error);
    return { ...token, error: 'ErrorRefresh' };
  }
}

// Функция для декодирования токена
export function decodeToken(accessToken: string) {
  return jwt.decode(accessToken);
}

// async function finalSignout(token: JWT) {
// if (token.provider == keycloak.id) {
//   try {
//     const issuerUrl = keycloak.options!.issuer!;
//     const logOutUrl = new URL(`${issuerUrl}/protocol/openid-connect/logout`);
//     logOutUrl.searchParams.set("id_token_hint", token.id_token);
//     const { status, statusText } = await fetch(logOutUrl);
//     console.log("Completed post-logout handshake", status, statusText);
//   } catch (e: any) {
//     console.error("Unable to perform post-logout handshake", e?.code || e);
//   }
// }
// }
