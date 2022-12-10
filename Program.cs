using AdysTech.CredentialManager;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using System;
using System.IO;
using System.Linq;
using System.Net;
using Windows.Security.Credentials.UI;

string? localUser = null;
for (int i = 0; i < args.Length; i++)
{
	if ((args[i] == "--local-user" || args[i].StartsWith('-') && args[i].Contains('u')) && i + 1 < args.Length)
	{
		localUser = args[++i];
	}
}

if (localUser is null)
{
	Console.Error.WriteLine("Error: Must provide a local user (--local-user, -u)");
	Environment.Exit(1);
	return;
}

var privateKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".Hello", $"{localUser}.pk");
if (!File.Exists(privateKeyPath))
{
	Console.Error.WriteLine($"Error: Could not find a private key for {localUser} ({privateKeyPath})");
	Environment.Exit(1);
	return;
}

var credentialsTarget = $"Hello/{localUser}";

var credentials = CredentialManager.GetCredentials(credentialsTarget);

if (credentials is null)
{
	var credentialsResponse = await CredentialPicker.PickAsync(new CredentialPickerOptions
	{
		Caption = "PGP passphrase",
		TargetName = credentialsTarget,
		Message = "Blank username and private key passphrase",
		AuthenticationProtocol = AuthenticationProtocol.Basic,
		CallerSavesCredential = true,
		CredentialSaveOption = CredentialSaveOption.Selected,
	});

	if (credentialsResponse.ErrorCode != 0)
	{
		Console.Error.WriteLine("Error: Could not retrieve private key passphrase");
		Environment.Exit(1);
		return;
	}

	credentials = new NetworkCredential { Password = credentialsResponse.CredentialPassword };

	if (credentialsResponse.CredentialSaveOption == CredentialSaveOption.Selected)
	{
		CredentialManager.SaveCredentials(credentialsTarget, credentials);
	}
}
else
{
	var verificationResult = await UserConsentVerifier.RequestVerificationAsync("Verify for PGP signing");
	if (verificationResult != UserConsentVerificationResult.Verified)
	{
		Console.Error.WriteLine("Error: Could not verify identity");
		Environment.Exit(1);
		return;
	}
}

for (var parent = ParentProcessUtils.GetParentProcess(); parent is not null; parent = ParentProcessUtils.GetParentProcess(parent))
{
	if (parent.MainWindowHandle > 0)
	{
		WindowManagerUtils.SetForegroundWindow(parent.MainWindowHandle);
		break;
	}
}

using var privateKeyFile = File.OpenRead(privateKeyPath);
var keyBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyFile));
var secretKey = keyBundle.GetKeyRings()
	.Cast<PgpSecretKeyRing>()
	.SelectMany(ring => ring.GetSecretKeys().Cast<PgpSecretKey>())
	.OrderByDescending(k => (k.IsSigningKey ? 2 : 0) + (k.PublicKey.IsMasterKey ? 1 : 0) + (k.PublicKey.GetSignatures().Cast<PgpSignature>().Any(s => s.HasSubpackets && (s.GetHashedSubPackets().GetKeyFlags() & KeyFlags.SignData) > 0) ? 2 : 0))
	.First();
var privateKey = secretKey.ExtractPrivateKey(credentials.Password.ToCharArray());

var signGen = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
signGen.InitSign(PgpSignature.CanonicalTextDocument, privateKey);
foreach (string userId in secretKey.PublicKey.GetUserIds())
{
	var userSubGen = new PgpSignatureSubpacketGenerator();
	userSubGen.SetSignerUserId(false, userId);
	signGen.SetHashedSubpackets(userSubGen.Generate());
	break;
}

using var input = Console.OpenStandardInput();
int ch;
while ((ch = input.ReadByte()) >= 0)
{
	signGen.Update((byte)ch);
}

using var armoredOutput = new ArmoredOutputStream(Console.OpenStandardOutput());
var bcpgOutput = new BcpgOutputStream(armoredOutput);
signGen.Generate().Encode(bcpgOutput);
