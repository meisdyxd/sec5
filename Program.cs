using System.Buffers.Binary;
using System.Security.Cryptography;
using Solutions.DesLabs;

namespace Lab5;

internal static class Program
{
    private static readonly byte[] DefaultKey = Convert.FromHexString("133457799BBCDFF1"); // Учебный ключ DES.

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length < 3) // Требуются команда, входной и выходной файлы.
            {
                Console.WriteLine("Использование: dotnet run -- encrypt|decrypt вход.bin выход.bin [ключHEX] [IVHEX]");
                return 1;
            }

            bool decrypt = args[0].Equals("decrypt", StringComparison.OrdinalIgnoreCase); // Выбирает обратное преобразование.
            if (!decrypt && !args[0].Equals("encrypt", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Команда должна быть encrypt или decrypt.");
            byte[] input = File.ReadAllBytes(args[1]); // Загружает исходные байты.
            byte[] key = args.Length > 3 ? Convert.FromHexString(args[3]) : DefaultKey; // Берёт ключ из аргумента либо использует учебный.
            byte[] iv = args.Length > 4 ? Convert.FromHexString(args[4]) : GenerateIv(); // Берёт IV либо генерирует по параметрам лабы 3.
            byte[] output = Transform(input, key, iv, decrypt); // Выполняет CBC.
            File.WriteAllBytes(args[2], output); // Сохраняет результат без преобразования в текст.
            Console.WriteLine($"Режим: DES-CBC; IV: {Convert.ToHexString(iv)}; результат: {Convert.ToHexString(output)}"); // Показывает проверочные значения.
            return 0;
        }
        catch (Exception error) when (error is ArgumentException or IOException or FormatException or CryptographicException)
        {
            Console.Error.WriteLine("Ошибка: " + error.Message); // Печатает понятное описание ошибки.
            return 1;
        }
    }

    private static byte[] Transform(byte[] input, byte[] key, byte[] iv, bool decrypt)
    {
        if (key.Length != 8) throw new ArgumentException("Ключ DES должен содержать 8 байтов."); // Проверяет длину ключа.
        if (iv.Length != 8) throw new ArgumentException("IV должен содержать 8 байтов."); // Проверяет длину вектора.
        if (input.Length % 8 != 0) throw new ArgumentException("Для CBC длина данных должна быть кратна 8 байтам; дополнение не используется."); // Не дополняет последний блок.

        var des = new DesCipher(key); // Подготавливает DES-ключи раундов.
        byte[] output = new byte[input.Length]; // Результат имеет ту же длину, что и вход.
        ulong previous = BinaryPrimitives.ReadUInt64BigEndian(iv); // Начальное значение цепочки CBC.

        for (int offset = 0; offset < input.Length; offset += 8) // Обрабатывает данные по 8 байтов.
        {
            ulong block = BinaryPrimitives.ReadUInt64BigEndian(input.AsSpan(offset, 8)); // Читает текущий блок.
            ulong result;
            if (decrypt) // При расшифровании сначала применяет обратный DES.
            {
                result = des.DecryptBlock(block) ^ previous; // Снимает связь с предыдущим шифроблоком.
                previous = block; // Следующий блок использует этот шифроблок.
            }
            else // При шифровании сначала связывает открытый блок с цепочкой.
            {
                result = des.EncryptBlock(block ^ previous); // XOR с IV/предыдущим шифроблоком и DES.
                previous = result; // Запоминает новый шифроблок.
            }
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), result); // Записывает обработанный блок.
        }

        return output; // Возвращает итоговый массив.
    }

    private static byte[] GenerateIv()
    {
        byte[] iv = new byte[8]; // В лабораторной IV состоит из восьми байтов.
        int value = 41; // Начальное состояние генератора из лабы 3.
        for (int i = 0; i < iv.Length; i++) // Генерирует каждый байт отдельно.
        {
            iv[i] = (byte)value; // Записывает текущее состояние как байт гаммы.
            value = (17 * value + 39) % 256; // Переходит к следующему состоянию датчика.
        }
        return iv; // Возвращает IV 29E0079EA51C035A.
    }
}
