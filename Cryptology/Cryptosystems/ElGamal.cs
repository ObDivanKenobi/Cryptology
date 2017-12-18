using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace Cryptology.Cryptosystems
{
    /* Параметры:
     * p - случайное простое число
     * g - примитивный элемент в Zp
     * x - случайное число из {1 ... p-1}
     * y = g^x mod p
     * 
     * Шифрование:
     * сообщение Q должно быть меньше p
     * выбирается сессионный ключ k из {1 ... p-1}
     * вычисляются a = g^k mod p, b = Q*y^k mod p
     * пара a-b — шифротекст
     * 
     * Расшифровка:
     * Q = b(a^x)^-1 mod p
     * 
     * Шифротекст: a и b
     * Открытый ключ: y, g, p
     * Секретный ключ: x
     */

    /// <summary>
    /// Набор методов для работы с шифрванием Эль-Гамаля.
    /// </summary>
    public class ElGamal
    {
        #region Not static
        internal int P { get; }
        internal int G { get; }
        internal int X { get; }
        internal int Y { get; }

        /// <summary>
        /// Открытый ключ
        /// </summary>
        public (int, int, int) OpenKey { get => (Y, G, P); }

        /// <summary>
        /// Создание нового экземпляра класса, отвечающего за шифрование Эль-Гамаля.
        /// </summary>
        /// <param name="p">простое число</param>
        /// <param name="g">примитивный элемент в Zp</param>
        /// <param name="x">случайное число</param>
        public ElGamal(int p, int g, int x)
        {
            P = p;
            G = g;
            X = x;
            Y = Calculations.ModPow(g, x, p);
        }

        /// <summary>
        /// Создание нового экземпляра класса, отвечающего за шифрование Эль-Гамаля.
        /// </summary>
        /// <param name="p">простое число</param>
        /// <param name="g">примитивный элемент в Zp</param>
        /// <param name="x">случайное число</param>
        /// <param name="y">элемент открытого ключа</param>
        public ElGamal(int p, int g, int y, int x)
        {
            P = p;
            G = g;
            X = x;
            Y = y;
        }

        /// <summary>
        /// Шифрование сообщения <paramref name="Q"/> по схеме Эль-Гамаля.
        /// </summary>
        /// <param name="Q">сообщение</param>
        /// <param name="k">сессионный ключ</param>
        /// <returns>шифротекст вида <code>(</code></returns>
        public (int a, int b) Encrypt(int Q, int k)
        {
            int a = Calculations.ModPow(G, k, P),
                b = (int)(Q * BigInteger.Pow(Y, k) % P);

            return (a, b);
        }

        /// <summary>
        /// Дешифровка шифротекста (<paramref name="a"/>, <paramref name="b"/>).
        /// </summary>
        /// <returns>дешифрованное сообщение</returns>
        public int Decode(int a, int b)
        {
            int ax = (int)Math.Pow(a, X);
            return b * Calculations.Invert(ax, P) % P;
        }

        /// <summary>
        /// Дешифровка шифротекста <paramref name="message"/>.
        /// </summary>
        /// <returns>дешифрованное сообщение</returns>
        public int Decode((int a, int b) message)
        {
            int ax = (int)Math.Pow(message.a, X);
            return message.b * Calculations.Invert(ax, P) % P;
        }
        #endregion

        /// <summary>
        /// Шифрование сообщения <paramref name="Q"/> с использованием открытого
        /// ключа <paramref name="openKey"/> и сессионного ключа <paramref name="k"/>.
        /// </summary>
        /// <param name="Q">сообщение</param>
        /// <param name="openKey">открытый ключ</param>
        /// <param name="k">сессионный ключ</param>
        /// <returns>шифротекст</returns>
        public static (int a, int b) Encrypt(int Q, (int p, int g, int y) openKey, int k)
        {
            int a = Calculations.ModPow(openKey.g, k, openKey.p),
                b = (int)(Q * BigInteger.Pow(openKey.y, k) % openKey.p);

            return (a, b);
        }

        /// <summary>
        /// Дешифрование шифротекста <paramref name="message"/> с использованием
        /// открытого ключа <paramref name="openKey"/> и сессионного ключа <paramref name="k"/>.
        /// </summary>
        /// <remarks>Нахождение дискретного логарифма полным перебором.</remarks>
        /// <param name="openKey">открытый ключ</param>
        /// <param name="message">шифротекст</param>
        /// <param name="k">сессионный ключ</param>
        /// <returns></returns>
        public static int DecryptBruteforce((int p, int g, int y) openKey, (int a, int b) message, int k)
        {
            return Decrypt(openKey, message, k, CalculateSecretKeyBruteforce(openKey));
        }

        /// <summary>
        /// Дешифрование шифротекста <paramref name="message"/> с использованием
        /// открытого ключа <paramref name="openKey"/> и сессионного ключа <paramref name="k"/>.
        /// </summary>
        /// <remarks>Нахождение дискретного логарифма с помощью алгоритма Шэнкса.</remarks>
        /// <param name="openKey">открытый ключ</param>
        /// <param name="message">шифротекст</param>
        /// <param name="k">сессионный ключ</param>
        /// <returns></returns>
        public static int DecryptShanksMethod((int p, int g, int y) openKey, (int a, int b) message, int k)
        {
            return Decrypt(openKey, message, k, CalculateSecretKeyShanksMethod(openKey));
        }

        public static int CalculateSecretKeyBruteforce(int p, int g, int y)
        {
            return Calculations.DiscreteLogarithmBruteforce(g, y, p);
        }

        public static int CalculateSecretKeyBruteforce((int p, int g, int y) openKey)
        {
            return Calculations.DiscreteLogarithmBruteforce(openKey.g, openKey.y, openKey.p);
        }

        public static int CalculateSecretKeyShanksMethod(int p, int g, int y)
        {
            return Calculations.DiscreteLogarithmShanksMethod(g, y, p);
        }

        public static int CalculateSecretKeyShanksMethod((int p, int g, int y) openKey)
        {
            return Calculations.DiscreteLogarithmShanksMethod(openKey.g, openKey.y, openKey.p);
        }

        public static string Help()
        {
            return Resources.HelpFiles.ElGamal;
        }

        static int Decrypt((int p, int g, int y) openKey, (int a, int b) message, int k, int secretKey)
        {
            ElGamal tmp = new ElGamal(openKey.p, openKey.g, openKey.y, secretKey);
            return tmp.Decode(message);
        }

        /// <summary>
        /// Дешифрование шифротекста (a, b2) на основе одинакового сессионного ключа
        /// и дешифрованного сообщения 1.
        /// </summary>
        /// <remarks>
        /// Из-за одинакового k a1 = a2 = a;
        /// Q2 = b2(a2^x)^-1 mod p = b2(a^x)^-1 mod p
        /// Выразим (a^x)^-1 из Q1: (a^x)^-1 = Q1*b1^-1 mod p
        /// Тогда Q2 = b2*Q1*b1^-1 mod p
        /// </remarks>
        /// <param name="b1">часть шифротекста 1</param>
        /// <param name="b2">часть шифротекста 2</param>
        /// <param name="Q1">сообщение 1</param>
        /// <param name="p">модуль</param>
        /// <returns>сообщение 2</returns>
        public static int Decrypt(int b1, int b2, int Q1, int p)
        {
            return Calculations.ModMultiply(p, b2, Q1, Calculations.InvertNotCoprimeIntegers(b1, p));
        }
    }
}
