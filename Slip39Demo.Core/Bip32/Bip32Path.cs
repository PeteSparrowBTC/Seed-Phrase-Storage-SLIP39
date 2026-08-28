using CSharpFunctionalExtensions;

namespace Slip39Demo.Core.Bip32;

// One element of a derivation path: the index as written, plus whether it is hardened.
// Index is the number BEFORE the hardened offset is applied, which is what a human
// reads and writes ("48h" is index 48, hardened), and ChildNumber is the 32-bit value
// BIP-32 actually feeds into the derivation.
public sealed record Bip32PathElement(uint Index, bool Hardened)
{
    public const uint HardenedOffset = 0x80000000;

    public uint ChildNumber => Hardened ? Index + HardenedOffset : Index;
}

// A BIP-32 derivation path, parsed from the form people write it in.
//
// Both hardened markers are accepted on input: the apostrophe (m/48'/0'/0'/2') because
// that is what BIP-48 and every wallet UI uses, and the letter h (m/48h/0h/0h/2h)
// because BIP-380 allows it in descriptors and it survives a shell without quoting.
// Output is deliberately asymmetric: ToString renders apostrophes for display next to
// the field the user typed, DescriptorForm renders h because that is what goes inside a
// descriptor's key origin brackets.
//
// Parse returns a Result rather than throwing. A path arrives here from a text box, so
// a malformed one is an expected outcome, and the message is shown to the owner.
public sealed record Bip32Path
{
    public IReadOnlyList<Bip32PathElement> Elements { get; }

    Bip32Path(IReadOnlyList<Bip32PathElement> elements) =>
        Elements = elements;

    // The largest index that can be written before the hardened offset is added.
    // 2147483647h is a real BIP-32 test vector, and its child number is uint.MaxValue.
    const uint MaxIndex = Bip32PathElement.HardenedOffset - 1;

    public static Result<Bip32Path> Parse(string? input)
    {
        var text = (input ?? "").Trim();

        if (text.Length == 0)
            return Result.Failure<Bip32Path>("the derivation path is empty.");

        var parts = text.Split('/');

        // A leading "m" (or "M") is the master key. Nothing else may start a path: a
        // path relative to an unnamed parent would silently derive from whatever this
        // code happened to hold.
        if (parts[0] is not ("m" or "M"))
            return Result.Failure<Bip32Path>(
                $"the derivation path must start with m, as in m/48'/0'/0'/2' (got \"{text}\").");

        var elements = new List<Bip32PathElement>();

        foreach (var part in parts.Skip(1))
        {
            if (part.Length == 0)
                return Result.Failure<Bip32Path>(
                    $"the derivation path has an empty element, so it carries a stray slash (\"{text}\").");

            var hardened = part[^1] is '\'' or 'h' or 'H';
            var digits = hardened ? part[..^1] : part;

            if (digits.Length == 0 || digits.Any(ch => !char.IsAsciiDigit(ch)))
                return Result.Failure<Bip32Path>(
                    $"\"{part}\" is not a derivation path element. Each element is a number, "
                    + "optionally followed by ' or h to mark it hardened.");

            if (!uint.TryParse(digits, out var index) || index > MaxIndex)
                return Result.Failure<Bip32Path>(
                    $"\"{part}\" is out of range: a path element is at most {MaxIndex}.");

            elements.Add(new Bip32PathElement(index, hardened));
        }

        return new Bip32Path(elements);
    }

    // m/48'/0'/0'/2', the form wallets show and the form the owner typed.
    public override string ToString() =>
        string.Concat(Elements.Select(e => $"/{e.Index}{(e.Hardened ? "'" : "")}").Prepend("m"));

    // 48h/0h/0h/2h: what goes between the fingerprint and the closing bracket of a
    // descriptor key origin. No leading m, no leading slash, h rather than apostrophe.
    public string DescriptorForm =>
        string.Join('/', Elements.Select(e => $"{e.Index}{(e.Hardened ? "h" : "")}"));
}
