using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptology
{
    /*
        Супервозрастающая последовательность: w_(k+1) = Sum(i = 1..k)(w_i)
        
        Шифрование:        
        Исходный текст представляется в двоичном виде и разбивается на блоки,
        равные по длине с открытым ключом.
        Далее из последовательности, образующей открытый ключ, выбираются 
        только те элементы, которые по порядку соответствуют 1 в двоичной 
        записи исходного текста, игнорируя при этом элементы, 
        соответствующие 0 биту. 
        После этого элементы полученного подмножества складываются. 
        Найденная в результате сумма и есть шифротекст.
        
        I. Генерация ключа
        w = (w1...wn) - супервозрастающая
        взаимно простые q и r, q > Sum(w)
        
        открытый ключ b = (b_1...b_n), b_i = r*w_i mod q
        закрытый ключ: (w, q, r)
        
        II. Шифрование
        a - n-битное сообщение, a_i in {0,1};
        шифротекст: x = Sum(a_i*b_i)

        III. Расшифровка
        s = r^-1 mod q
        c = x*s mod q
        Выбрать наибольший элемент w1 из w, который меньше, чем c, и вычислить
        c1 = c - w1. Далее выбирает следующий наибольший элемент, 
        w2? который меньше, чем c1, повторять, пока разность не станет равной 
        нулю.

        Выбранные из w элементы - 1 в двоичной записи исходного текста.
    */
    public class MerkleHellman
    {
        /// <summary>
        /// Шифрование сообщения <paramref name="s"/>.
        /// </summary>
        /// <param name="s">сообщение</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        public static int[] Encrypt(string s, int[] w, int q, int r)
        {
            int[] b = new int[w.Length];
            for (int i = 0; i < b.Length; ++i)
                b[i] = Calculations.ModMultiply(r, w[i], q);

            int[] x = new int[s.Length];
            for (int i = 0; i < s.Length; ++i)
                x[i] = Encrypt(s[i], b, w, q, r);

            return x;
        }

        /// <summary>
        /// Шифрование символа <paramref name="symbol"/>.
        /// </summary>
        /// <param name="symbol">символ</param>
        /// <param name="b">открытый ключ</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        public static int Encrypt(char symbol, int[] b, int[] w, int q, int r)
        {
            CharToBitsConverter converter = new CharToBitsConverter('А', 6);
            byte[] bits = converter.ToBits(symbol);

            int c = 0;
            for (int i = 0; i < w.Length; ++i)
                c += bits[i] * b[i];

            return c;
        }

        /// <summary>
        /// Шифрование сообщения <paramref name="s"/> с использованием конвертера.
        /// </summary>
        /// <param name="s">сообщение</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        /// <param name="converter">преобразователь символа в массив битов</param>
        public static int[] Encrypt(string s, int[] w, int q, int r, CharToBitsConverter converter)
        {
            int[] b = new int[w.Length];
            for (int i = 0; i < b.Length; ++i)
                b[i] = Calculations.ModMultiply(r, w[i], q);

            int[] x = new int[s.Length];
            for (int i = 0; i < s.Length; ++i)
                x[i] = Encrypt(s[i], b, w, q, r, converter);

            return x;
        }

        /// <summary>
        /// Шифрование символа <paramref name="symbol"/>.
        /// </summary>
        /// <param name="symbol">символ</param>
        /// <param name="b">открытый ключ</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        /// <param name="converter">преобразователь символа в массив битов</param>
        public static int Encrypt(char symbol, int[] b, int[] w, int q, int r, CharToBitsConverter converter)
        {
            byte[] bits = converter.ToBits(symbol);

            int c = 0;
            for (int i = 0; i < w.Length; ++i)
                c += bits[i] * b[i];

            return c;
        }

        /// <summary>
        /// Расшифровать сообщение <paramref name="x"/>.
        /// </summary>
        /// <param name="x">сообщение</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        public static string Decrypt(int[] x, int[] w, int q, int r)
        {
            char[] message = new char[x.Length];

            int s = Calculations.InvertNotCoprimeIntegers(r, q);
            for (int i = 0; i < x.Length; ++i)
                message[i] = Decrypt(x[i], w, s, q);

            return new string(message);
        }

        /// <summary>
        /// Расшифровать символ <paramref name="x"/>.
        /// </summary>
        /// <param name="x">зашифрованный символ</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="s">обратное к r по модулю q</param>
        /// <param name="q">часть закрытого ключа</param>
        static char Decrypt(int x, int[] w, int s, int q)
        {
            byte[] bits = new byte[w.Length];
            int c = Calculations.ModMultiply(x, s, q);
            while (c > 0)
            {
                int i = w.Length - 1;
                while (i >= 0 && w[i] > c) --i;
                if (i < 0)
                    break;
                c -= w[i];
                bits[i] = 1;
            }

            CharToBitsConverter converter = new CharToBitsConverter('А', 6);
            return converter.ToChar(bits);
        }

        /// <summary>
        /// Расшифровать сообщение <paramref name="x"/>с использованием заданного 
        /// конвертера <paramref name="converter"/>.
        /// </summary>
        /// <param name="x">сообщение</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="r">часть закрытого ключа</param>
        /// <param name="converter">преобразователь массива битов в символ</param>
        public static string Decrypt(int[] x, int[] w, int q, int r, CharToBitsConverter converter)
        {
            char[] message = new char[x.Length];

            int s = Calculations.InvertNotCoprimeIntegers(r, q);
            for (int i = 0; i < x.Length; ++i)
                message[i] = Decrypt(x[i], w, s, q, converter);

            return new string(message);
        }

        /// <summary>
        /// Расшифровать символ <paramref name="x"/> с использованием заданного 
        /// конвертера <paramref name="converter"/>.
        /// </summary>
        /// <param name="x">зашифрованный символ</param>
        /// <param name="w">последовательность - часть закрытого ключа</param>
        /// <param name="s">обратное к r по модулю q</param>
        /// <param name="q">часть закрытого ключа</param>
        /// <param name="converter">преобразователь массива битов в символ</param>
        static char Decrypt(int x, int[] w, int s, int q, CharToBitsConverter converter)
        {
            byte[] bits = new byte[w.Length];
            int c = Calculations.ModMultiply(x, s, q);
            while (c > 0)
            {
                int i = w.Length - 1;
                while (i >= 0 && w[i] > c) --i;
                if (i < 0)
                    break;
                c -= w[i];
                bits[i] = 1;
            }

            return converter.ToChar(bits);
        }
    }

    [Obsolete("Класс больше не используется, используйте класс CharToBitsConverter.", false)]
    public class SixBitRussianChar
    {
        static char FirstRussianLetter = 'А';

        public byte[] Bits { get; set; }

        public SixBitRussianChar(char ch)
        {
            Bits = new byte[6];
            var t = BitConverter.GetBytes(Math.Abs(Char.ToUpper(ch) - FirstRussianLetter + 1));
            var tmp = new BitArray(BitConverter.GetBytes(Char.ToUpper(ch) - FirstRussianLetter + 1));

            for (int i = 0; i < 6; ++i)
                Bits[6 - i - 1] = (byte)(tmp[i] ? 1 : 0);
        }

        public SixBitRussianChar(byte[] bits)
        {
            if (bits.Length != 6)
                throw new ArgumentException("Допустимы только шестибитные значения");
            Bits = bits;
        }

        public char ToChar()
        {
            int delta = 0,
                pow = 1;
            for (int i = Bits.Length - 1; i >= 0; --i)
            {
                if (Bits[i] != 0)
                    delta += pow;
                pow *= 2;
            }

            int tmp = FirstRussianLetter + delta - 1;
            return (char)(FirstRussianLetter + delta - 1);
        }
    }

    /// <summary>
    /// Преобразует символ в массив битов заданной длины (и наоборот). 
    /// </summary>
    public class CharToBitsConverter
    {
        public char FirstChar { get; }
        public int Length { get; }
        public int Shift { get; }

        /// <summary>
        /// Создание экземпляра конвертера.
        /// </summary>
        /// <param name="firstChar">первый символ из числа конвертируемых</param>
        /// <param name="length">длина битового массива</param>
        /// <param name="shift">сдвиг относительно нулевого значения</param>
        /// <example>
        /// <code>CharToBitConverter('A', 5, 1)</code> будет конвертировать
        /// символы в массив битов длиной 5, начиная с русской А, 
        /// которая преобразуется в значение 00001.
        /// </example>
        public CharToBitsConverter(char firstChar, int length, int shift = 0)
        {
            FirstChar = firstChar;
            Length = length;
            Shift = shift;
        }

        /// <summary>
        /// Преобразование <paramref name="ch"/> в массив битов.
        /// </summary>
        public byte[] ToBits(char ch)
        {
            byte[] bits = new byte[Length];
            var tmp = new BitArray(BitConverter.GetBytes(Char.ToUpper(ch) - FirstChar + Shift));

            for (int i = 0; i < Length; ++i)
                bits[Length - i - 1] = (byte)(tmp[i] ? 1 : 0);

            return bits;
        }

        /// <summary>
        /// Преобразование массива битов <paramref name="bits"/> в соответствующий символ.
        /// </summary>
        public char ToChar(byte[] bits)
        {
            if (bits.Length != Length)
                throw new ArgumentException("Длина массива битов должна соответствовать заданному значению конвертера.");

            int delta = 0,
                pow = 1;

            for(int i = bits.Length - 1; i >= 0; --i)
            {
                if (bits[i] != 0)
                    delta += pow;
                pow *= 2;
            }

            return (char)(FirstChar + delta - Shift);
        }
    }
}
