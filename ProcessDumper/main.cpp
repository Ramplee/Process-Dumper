#include "Dumper/ProcessDumper.hpp"
#include <conio.h>

void PrintStatus(ProcessDumper& Dumper) {
	const uint64_t Decrypted = Dumper.GetDecryptedCount();
	const uint64_t Total = Dumper.GetTotalPages();
	const double Percent = (Total > 0)
		? (static_cast<double>(Decrypted) * 100.0 / static_cast<double>(Total))
		: 0.0;
	printf("\r  [Monitor] Decrypted: %llu / %llu pages (%.2f%%)    ",
		Decrypted,
		Total,
		Percent);
}

int main(int argc, char* argv[]) {

	std::string TargetProcess;
	float Threshold = 1.0f;

	for (int i = 1; i < argc; i++) {
		std::string Arg = argv[i];
		if ((Arg == "-t" || Arg == "--threshold") && i + 1 < argc) {
			Threshold = std::stof(argv[++i]);
		}
		else if (TargetProcess.empty()) {
			TargetProcess = Arg;
		}
	}

	if (TargetProcess.empty()) {
		printf("Usage: ProcessDumper.exe <process.exe> [-t threshold]\n");
		printf("-t  Auto-stop at decryption %% (0.5 = 50%%, 1.0 = 100%%). Default: F7 to stop manually.\n");
		printf("  Enter process name (game.exe): ");
		std::getline(std::cin, TargetProcess);
	}

	if (TargetProcess.empty()) {
		log("No process name provided");
		return 1;
	}

	printf("\n");
	log("Target: %s", TargetProcess.c_str());

	ProcessDumper Dumper;
	Dumper.SetDecryptionThreshold(Threshold);

	if (Threshold < 1.0f)
		log("Auto-stop at %.0f%% decryption", Threshold * 100.0f);

	if (!Dumper.Attach(TargetProcess)) {
		log("Failed to attach to process");
		system("pause");
		return 1;
	}

	if (!Dumper.StartMonitoring()) {
		log("Failed to start monitoring");
		system("pause");
		return 1;
	}

	printf("\n");
	log("Monitoring page decryptions...");
	log("Press F7 to stop and dump current state\n");

	while (Dumper.IsMonitoring()) {
		PrintStatus(Dumper);

		if (Threshold < 1.0f && Dumper.GetDecryptionProgress() >= Threshold) {
			printf("\n");
			log("Reached %.0f%% decryption threshold - auto stopping", Threshold * 100.0f);
			break;
		}

		if (_kbhit()) {
			int Key = _getch();
			if (Key == 0 || Key == 224) {
				int Extended = _getch();
				if (Extended == 65) // F7
					break;
			}
		}

		Sleep(100);
	}

	printf("\n\n");
	log("Stopping monitor...");
	Dumper.DumpCurrent();

	size_t DotPos = TargetProcess.find_last_of('.');
	std::string BaseName = (DotPos != std::string::npos)
		? TargetProcess.substr(0, DotPos)
		: TargetProcess;

	std::string OutputPath = "dumped_" + BaseName + ".exe";

	log("Rebuilding PE...");
	if (Dumper.Rebuild(OutputPath)) {
		printf("\n");
		log("Dump successful: %s", OutputPath.c_str());
	}
	else {
		log("Failed to rebuild PE");
	}

	printf("\n");
	system("pause");
	return 0;
}
