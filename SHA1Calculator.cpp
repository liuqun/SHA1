#include <stdint.h>
#include <cassert>

#include "SHA1.h"

SHA1Calculator::SHA1Calculator() {
	this->context = new SHA1Context;
	assert(this->context);
	(void) SHA1Reset(this->context);
}

SHA1Calculator::~SHA1Calculator() {
	delete this->context;
}

void SHA1Calculator::inputData(const uint8_t data[], ///< 输入数据
		unsigned int length ///< 输入数据长度
		) {
	int err;
	err = SHA1Input(this->context, data, length);
	if (err) {
		// TODO: 处理错误
	}
}

uint64_t SHA1Calculator::getTotalDataBits() {
	uint64_t total;

	total = this->context->Length_High;
	total <<= 32;
	total += this->context->Length_Low;
	return total;
}

void SHA1Calculator::inputEnd() {
	/* 结束数据输入: 当前的算法实现中此处无额外处理 */
}

void SHA1Calculator::getHashResult(uint8_t digest[SHA1HashSize], unsigned int& outSize) {
	SHA1Context snapshot; // 保存上下文状态当前的一份 snapshot

#if defined(__GNUC__)
	snapshot = *(this->context); // 对结构体进行整体复制(需要 C++ 编译器支持)
#endif
#if !defined(__GNUC__)
	memcpy(snapshot.Intermediate_Hash, this->context->Intermediate_Hash, sizeof(snapshot.Intermediate_Hash));
	snapshot.Length_Low = this->context->Length_Low;
	snapshot.Length_High = this->context->Length_High;
	snapshot.Message_Block_Index = this->context->Message_Block_Index;
	memcpy(snapshot.Message_Block, this->context->Message_Block, this->context->Message_Block_Index);
	snapshot.Computed = this->context->Computed;
	snapshot.Corrupted = this->context->Corrupted;
#endif

	/* Note: 此处只对快照备份数据进行 padding 操作并生成摘要, 不会修改原始数据 */
	int err;
	err = SHA1Result(&snapshot, digest);
	if (err) {
		// TODO: 处理错误
	}
	outSize = SHA1HashSize;
}

void SHA1Calculator::reset() {
	(void) SHA1Reset(this->context);
}
