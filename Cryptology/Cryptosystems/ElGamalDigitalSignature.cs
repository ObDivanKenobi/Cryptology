using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptology.Cryptosystems
{
    /* Работа съемы Эль-Гамаля в режиме ЭЦП
     * I. формирование открытого ключа (p, g, y) и выбор секретного
     * аналогичен основному режиму.
     * 
     * II. A ---(p, g, y)---> B
     * 1) A выбирает k из {1 ... p-1} взаимно простое с p
     * 2) r = g^k mod p
     * 3) s = (Q - x*r)k^-1 mod p-1
     * 4) (r, s) является подписью сообщения Q
     * 
     * III. проверка
     * A ---(Q, [r, s])---> B
     * 1) 0 <= r < p, 0 <= s < p-1
     * 2) y^r*r^s = g^Q mod p
     * Если выполняется, то это действительно А.
     */

    public class ElGamalDigitalSignature : ElGamal
    {
        public ElGamalDigitalSignature(int p, int g, int x) : base(p, g, x) { }
        public ElGamalDigitalSignature(int p, int g, int y, int x) : base(p, g, y, x) { }

        public (int r, int s) SignMessage(int Q, int k)
        {
            int r = Calculations.ModPow(G, k, P);
            BigInteger pow = (Q - X * r) * Calculations.Invert(k, P);
            int s = (int)(pow % (P - 1));

            return (r, s);
        }

        public static int FindS_Bruteforce(int Q, (int p, int g, int y) openKey, int r)
        {
            int k = Calculations.DiscreteLogarithmBruteforce(openKey.g, r, openKey.p);
            int x = CalculateSecretKeyBruteforce(openKey);
            return FindS(Q, x, r, k, openKey.p);
        }

        public static int FindS_Shanks(int Q, (int p, int g, int y) openKey, int r)
        {
            int k = Calculations.DiscreteLogarithmShanksMethod(openKey.g, r, openKey.p);
            int x = CalculateSecretKeyShanksMethod(openKey);
            return FindS(Q, x, r, k, openKey.p);
        }

        public static string Help()
        {
            return Resources.HelpFiles.ElGamalDigitalSignature;
        }

        static int FindS(int Q, int x, int r, int k, int p)
        {
            BigInteger pow = (Q - x * r) * Calculations.Invert(k, p);
            return (int)(pow % (p - 1));
        }
    }
}
