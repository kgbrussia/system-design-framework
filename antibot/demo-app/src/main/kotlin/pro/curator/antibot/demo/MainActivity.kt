package pro.curator.antibot.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun DemoScreen(vm: DemoViewModel = viewModel()) {
    val state = vm.state

    Scaffold(
        topBar = { TopAppBar(title = { Text("CURATOR AntiBot — demo host") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.baseUrl,
                onValueChange = vm::onBaseUrlChange,
                label = { Text("Server base URL") },
                singleLine = true,
                enabled = !state.connected && !state.busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "Tip: run the Ktor server, then use http://10.0.2.2:8080 from the emulator " +
                    "(10.0.2.2 = your host machine).",
                style = MaterialTheme.typography.bodySmall,
            )

            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::connect, enabled = !state.busy && !state.connected) {
                    Text("Connect & Init")
                }
                Button(onClick = vm::getToken, enabled = !state.busy && state.connected) {
                    Text("Get Trust Token")
                }
                Button(onClick = vm::callProtected, enabled = !state.busy && state.connected) {
                    Text("Call /v1/protected")
                }
                Button(onClick = vm::clearToken, enabled = !state.busy && state.connected) {
                    Text("Invalidate Token")
                }
            }

            if (state.busy) {
                CircularProgressIndicator()
            }

            Text("Log", style = MaterialTheme.typography.titleMedium)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                state.log.takeLast(200).forEach { line ->
                    Text(text = line, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
            }
        }
    }
}
