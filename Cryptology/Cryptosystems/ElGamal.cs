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
     * Шифротекст: a и b
     * Открытый ключ: y, g, p
     * Секретный ключ: x
     */

    /// <summary>
    /// Набор методов для работы с шифрванием Эль-Гамаля.
    /// </summary>
    public class ElGamal
    {
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
    }
}
