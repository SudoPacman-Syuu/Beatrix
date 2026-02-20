"""
BEATRIX Task Router - Distributes work between AI models

Haiku = Grunt work (fast, cheap, bulk)
Opus/Sonnet = Complex analysis (smart, expensive, strategic)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class TaskPriority(Enum):
    LOW = 1      # Haiku handles
    MEDIUM = 2   # Haiku or Sonnet
    HIGH = 3     # Sonnet
    CRITICAL = 4 # Opus


class TaskType(Enum):
    # Grunt work (Haiku)
    BULK_PARSE = "bulk_parse"
    RESPONSE_ANALYSIS = "response_analysis"
    ENDPOINT_EXTRACTION = "endpoint_extraction"
    PARAMETER_MINING = "parameter_mining"
    PATTERN_MATCHING = "pattern_matching"
    DATA_FORMATTING = "data_formatting"

    # Complex work (Sonnet/Opus)
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOIT_CHAIN = "exploit_chain"
    REPORT_WRITING = "report_writing"
    STRATEGIC_PLANNING = "strategic_planning"


@dataclass
class Task:
    """A task to be processed by AI"""
    id: str
    type: TaskType
    priority: TaskPriority
    data: Any
    callback: Optional[Callable] = None
    result: Any = None
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None


class TaskRouter:
    """Routes tasks to appropriate AI models"""

    # Task type to model mapping
    GRUNT_TASKS = {
        TaskType.BULK_PARSE,
        TaskType.RESPONSE_ANALYSIS,
        TaskType.ENDPOINT_EXTRACTION,
        TaskType.PARAMETER_MINING,
        TaskType.PATTERN_MATCHING,
        TaskType.DATA_FORMATTING,
    }

    def __init__(self, haiku_grunt=None, opus_commander=None):
        self.haiku = haiku_grunt
        self.opus = opus_commander
        self.task_queue: List[Task] = []
        self.completed_tasks: List[Task] = []

    def assign_model(self, task: Task) -> str:
        """Determine which model handles a task"""
        if task.type in self.GRUNT_TASKS:
            return "haiku"
        if task.priority == TaskPriority.CRITICAL:
            return "opus"
        if task.priority == TaskPriority.HIGH:
            return "sonnet"
        return "haiku"

    async def process_task(self, task: Task) -> Any:
        """Process a single task"""
        model = self.assign_model(task)

        if model == "haiku" and self.haiku:
            if task.type == TaskType.BULK_PARSE:
                result = await self.haiku.parse_recon_data(str(task.data))
            elif task.type == TaskType.RESPONSE_ANALYSIS:
                result = await self.haiku.analyze_responses(task.data)
            elif task.type == TaskType.ENDPOINT_EXTRACTION:
                result = await self.haiku.extract_endpoints(task.data)
            elif task.type == TaskType.PARAMETER_MINING:
                result = await self.haiku.extract_parameters(task.data)
            else:
                result = await self.haiku.complete(str(task.data))
        else:
            # Fallback or complex task - would use Opus/Sonnet
            result = {"status": "requires_advanced_model", "data": task.data}

        task.result = result
        task.status = "completed"
        task.completed_at = datetime.now()
        self.completed_tasks.append(task)

        if task.callback:
            task.callback(result)

        return result

    async def process_all(self) -> List[Any]:
        """Process all queued tasks"""
        results = []
        for task in self.task_queue:
            result = await self.process_task(task)
            results.append(result)
        self.task_queue = []
        return results

    def queue_task(self, task: Task):
        """Add task to queue"""
        self.task_queue.append(task)

    def status(self) -> Dict:
        """Get router status"""
        return {
            "queued": len(self.task_queue),
            "completed": len(self.completed_tasks),
            "haiku_available": self.haiku is not None,
        }
